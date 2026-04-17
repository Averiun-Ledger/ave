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
    response::RequestEventDB,
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
    create_nodes_and_connections, create_subject, emit_confirm, emit_eol,
    emit_fact, emit_fact_viewpoints, emit_reject, emit_transfer, get_events,
    get_subject, node_running,
};
use futures::future::join_all;
use serde_json::{from_value, json};
use test_log::test;

use crate::common::PORT_COUNTER;

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

#[test(tokio::test)]
// B01: arquitectura base y ausencia de acoples
//
// Setup:
//   crear un tracker y una governance;
//   preparar uno o dos witnesses;
//   dejar distintos `sn` locales en el nodo receptor.
//
// Acción:
//   lanzar `auth`, `update` y `distribution`.
//
// Comprobar:
//   el rango sale del register;
//   el arranque sale del `sn` local;
//   el batch size sale de config;
//   el tracker no se levanta salvo para servir la copia.
async fn test_viewpoints_architecture_battery() {
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

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
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
                        "AveNode2"
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

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "witness": [
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

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(witness, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    witness
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    witness.update_subject(subject_id.clone()).await.unwrap();

    let owner_state = get_subject(owner, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let witness_state = get_subject(witness, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert_eq!(
        owner_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        witness_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
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
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
        ],
    )
    .unwrap();
    assert_tracker_visibility(
        &witness_state,
        TrackerVisibilityModeDB::Full,
        vec![
            TrackerStoredVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 1,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let owner_events = get_events(owner, subject_id.clone(), 2, true)
        .await
        .unwrap();
    let witness_events = get_events(witness, subject_id.clone(), 2, true)
        .await
        .unwrap();

    assert_tracker_fact_full(
        &owner_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &witness_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );

    emit_fact(
        owner,
        subject_id.clone(),
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        true,
    )
    .await
    .unwrap();

    let owner_state = get_subject(owner, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let witness_state = get_subject(witness, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    assert_eq!(
        owner_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    assert_eq!(
        witness_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
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
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();
    assert_tracker_visibility(
        &witness_state,
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
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();

    let owner_events = get_events(owner, subject_id.clone(), 3, true)
        .await
        .unwrap();
    let witness_events = get_events(witness, subject_id.clone(), 3, true)
        .await
        .unwrap();

    assert_tracker_fact_full(
        &owner_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &[],
    );
    assert_tracker_fact_full(
        &witness_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &[],
    );
}

#[test(tokio::test)]
// B02: precedencia y composición de grants
//
// Setup:
//   usar el mismo witness con varios grants:
//   `AllViewpoints`, `Hash`, `agua`, `basura`, explícito y genérico.
//   añadir también grants con viewpoints que no existen o que no aparecen en
//   ningún fact del subject.
//   añadir también casos con grant `Full`.
//
// Acción:
//   pedir acceso o copia para ese witness.
//
// Comprobar:
//   `AllViewpoints` gana;
//   `Clear + Clear` une viewpoints;
//   `Hash` no rebaja un acceso ya ganado.
//   `Full` gana a `Clear` y `Hash`;
//   un viewpoint inexistente no abre nada;
//   un grant que no coincide con ningún fact útil no da claridad extra.
async fn test_viewpoints_grant_precedence_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = &nodes[0].api;
    let witness_mixed = &nodes[1].api;
    let witness_agua = &nodes[2].api;
    let witness_hash = &nodes[3].api;
    let witness_vidrio = &nodes[4].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![witness_mixed, witness_agua, witness_hash, witness_vidrio],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Mixed",
                    "key": witness_mixed.public_key()
                },
                {
                    "name": "Agua",
                    "key": witness_agua.public_key()
                },
                {
                    "name": "HashNode",
                    "key": witness_hash.public_key()
                },
                {
                    "name": "Vidrio",
                    "key": witness_vidrio.public_key()
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
                    "viewpoints": ["agua", "basura", "vidrio"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "Mixed", "Agua", "HashNode", "Vidrio"
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
                                "name": "Mixed",
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
                                        "name": "Mixed",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "Agua",
                                        "viewpoints": ["agua"]
                                    },
                                    {
                                        "name": "HashNode",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "Vidrio",
                                        "viewpoints": ["vidrio"]
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

    let _state =
        get_subject(witness_mixed, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(witness_agua, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(witness_hash, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(witness_vidrio, governance_id.clone(), Some(1), true)
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

    emit_fact(
        owner,
        subject_id.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        true,
    )
    .await
    .unwrap();

    let owner_state = get_subject(owner, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let mixed_state =
        get_subject(witness_mixed, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    let agua_state =
        get_subject(witness_agua, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    let hash_state =
        get_subject(witness_hash, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    let vidrio_state =
        get_subject(witness_vidrio, subject_id.clone(), Some(3), true)
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
    assert_eq!(
        mixed_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 3
        })
    );
    assert_eq!(
        agua_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        hash_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        vidrio_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &mixed_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();
    assert_tracker_visibility(
        &agua_state,
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
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();
    assert_tracker_visibility(
        &hash_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();
    assert_tracker_visibility(
        &vidrio_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();

    let mixed_events = get_events(witness_mixed, subject_id.clone(), 4, true)
        .await
        .unwrap();
    let agua_events = get_events(witness_agua, subject_id.clone(), 4, true)
        .await
        .unwrap();
    let hash_events = get_events(witness_hash, subject_id.clone(), 4, true)
        .await
        .unwrap();
    let vidrio_events = get_events(witness_vidrio, subject_id.clone(), 4, true)
        .await
        .unwrap();

    assert_eq!(mixed_events.len(), 4);
    assert_eq!(agua_events.len(), 4);
    assert_eq!(hash_events.len(), 4);
    assert_eq!(vidrio_events.len(), 4);

    assert_tracker_fact_full(
        &mixed_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &mixed_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["basura"],
    );
    assert_tracker_fact_full(
        &mixed_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );

    assert_tracker_fact_full(
        &agua_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_opaque(&agua_events[2].event, &["basura"]).unwrap();
    assert_tracker_fact_full(
        &agua_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );

    assert_tracker_fact_opaque(&hash_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_opaque(&hash_events[2].event, &["basura"]).unwrap();
    assert_tracker_fact_full(
        &hash_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );

    assert_tracker_fact_opaque(&vidrio_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_opaque(&vidrio_events[2].event, &["basura"]).unwrap();
    assert_tracker_fact_full(
        &vidrio_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );
}

#[test(tokio::test)]
// B03: huecos históricos y cambios múltiples de viewpoint
//
// Setup:
//   dar acceso `agua`;
//   quitar el testigo;
//   volver a dar acceso `basura`;
//   meter facts y non-facts entre medias;
//   añadir un tramo con un viewpoint inexistente o irrelevante.
//
// Acción:
//   pedir el histórico completo.
//
// Comprobar:
//   tramo 1 en claro;
//   hueco en `Hash`;
//   tramo 2 en claro;
//   el hueco no hereda el viewpoint siguiente.
//   un tramo con viewpoint inexistente sigue en `Hash`.
//   si entre cambios no hay facts, no aparece un tramo fantasma.
async fn test_viewpoints_historical_gaps_battery() {
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

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "GapWitness",
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
                        "GapWitness"
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
                                        "name": "GapWitness",
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

    let _state = get_subject(witness, governance_id.clone(), Some(1), true)
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

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": []
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

    let _state = get_subject(witness, governance_id.clone(), Some(2), true)
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
        BTreeSet::from(["agua".to_owned()]),
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
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "GapWitness",
                                        "viewpoints": ["basura"]
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

    let _state = get_subject(witness, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_id.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        BTreeSet::from(["basura".to_owned()]),
        true,
    )
    .await
    .unwrap();

    let owner_state = get_subject(owner, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let witness_state = get_subject(witness, subject_id.clone(), Some(3), true)
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
    assert_eq!(
        witness_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
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
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["basura".to_owned()],
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
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
        ],
    )
    .unwrap();
    assert_tracker_visibility(
        &witness_state,
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
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["basura".to_owned()],
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
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let owner_events = get_events(owner, subject_id.clone(), 4, true)
        .await
        .unwrap();
    let witness_events = get_events(witness, subject_id.clone(), 4, true)
        .await
        .unwrap();

    assert_eq!(owner_events.len(), 4);
    assert_eq!(witness_events.len(), 4);

    assert_tracker_fact_full(
        &owner_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &owner_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &owner_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &["basura"],
    );

    assert_tracker_fact_full(
        &witness_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_opaque(&witness_events[2].event, &["agua"]).unwrap();
    assert_tracker_fact_full(
        &witness_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &["basura"],
    );
}

#[test(tokio::test)]
// B04: ventana de búsqueda por batch
//
// Setup:
//   crear tres testigos explícitos por tramos:
//   uno hasta `5`, otro hasta `10` y otro hasta `15`;
//   el receptor entra como testigo al final;
//   fijar `ledger_batch_size = 10`.
//
// Acción:
//   lanzar un update sobre el receptor nuevo.
//
// Comprobar:
//   el update llega al `sn` más alto en un único intento;
//   el primer tramo público se aplica;
//   el segundo tramo público también se aplica;
//   el prefijo público se aplica;
//   el tramo con viewpoints privados llega opaco y congela `properties`.
async fn test_viewpoints_batch_window_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(5),
            ..Default::default()
        })
        .await;

    let owner = &nodes[0].api;
    let node_two = &nodes[1].api;
    let node_five = &nodes[2].api;
    let node_opaque = &nodes[3].api;
    let node_new = &nodes[4].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![node_two, node_five, node_opaque, node_new],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "NodeTwo",
                    "key": node_two.public_key()
                },
                {
                    "name": "NodeFive",
                    "key": node_five.public_key()
                },
                {
                    "name": "NodeOpaque",
                    "key": node_opaque.public_key()
                },
                {
                    "name": "NodeNew",
                    "key": node_new.public_key()
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
                    "viewpoints": ["agua"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "NodeTwo",
                        "NodeFive",
                        "NodeOpaque",
                        "NodeNew"
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
                                        "name": "NodeTwo",
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

    let _state = get_subject(node_two, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let _state = get_subject(node_five, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let _state = get_subject(node_opaque, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let _state = get_subject(node_new, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for data in 1..=2 {
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

    let json = json!({
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
                                        "name": "NodeFive",
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

    let _state = get_subject(node_two, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let _state = get_subject(node_five, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let _state = get_subject(node_opaque, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let _state = get_subject(node_new, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    for data in 3..=5 {
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

    let json = json!({
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
                                        "name": "NodeOpaque",
                                        "viewpoints": []
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

    let _state = get_subject(node_two, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let _state = get_subject(node_five, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let _state = get_subject(node_opaque, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let _state = get_subject(node_new, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    for data in 6..=8 {
        emit_fact_viewpoints(
            owner,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            BTreeSet::from(["agua".to_owned()]),
            true,
        )
        .await
        .unwrap();
    }

    let json = json!({
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
                                        "name": "NodeOpaque",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "NodeNew",
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

    let _state = get_subject(node_new, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    let node_two_state =
        get_subject(node_two, subject_id.clone(), Some(2), true)
            .await
            .unwrap();
    let node_five_state =
        get_subject(node_five, subject_id.clone(), Some(5), true)
            .await
            .unwrap();
    let node_opaque_state =
        get_subject(node_opaque, subject_id.clone(), Some(8), true)
            .await
            .unwrap();

    assert_eq!(
        node_two_state.properties,
        json!({
            "one": 2,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        node_five_state.properties,
        json!({
            "one": 5,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        node_opaque_state.properties,
        json!({
            "one": 5,
            "two": 0,
            "three": 0
        })
    );

    node_new
        .auth_subject(
            subject_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(&node_two.public_key()).unwrap(),
                PublicKey::from_str(&node_five.public_key()).unwrap(),
                PublicKey::from_str(&node_opaque.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();

    node_new.update_subject(subject_id.clone()).await.unwrap();

    let new_state = get_subject(node_new, subject_id.clone(), Some(8), true)
        .await
        .unwrap();
    assert_eq!(
        new_state.properties,
        json!({
            "one": 5,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &new_state,
        TrackerVisibilityModeDB::Opaque,
        vec![
            TrackerStoredVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(5),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 6,
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
                to_sn: Some(5),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 6,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let new_events = get_events(node_new, subject_id.clone(), 9, true)
        .await
        .unwrap();

    for data in 1..=5 {
        assert_tracker_fact_full(
            &new_events[data as usize].event,
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            &[],
        );
    }

    for data in 6..=8 {
        assert_tracker_fact_opaque(&new_events[data as usize].event, &["agua"])
            .unwrap();
    }
}

#[test(tokio::test)]
// B05: respuesta según el requester
//
// Setup:
//   hacer que el witness vea más que el requester;
//   por ejemplo witness con `agua+basura` y requester con solo `agua`.
//   añadir un requester con viewpoints vacíos o con viewpoints que no existen.
//
// Acción:
//   pedir el mismo rango desde requesters distintos.
//
// Comprobar:
//   el witness no devuelve más claridad de la que toca al requester;
//   lo no permitido sale opaco;
//   lo público sigue saliendo en claro.
//   requester con viewpoint inexistente no abre facts privados.
//   requester con `AllViewpoints` inválido no debe abrir nada especial.
async fn test_viewpoints_requester_perspective_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = nodes[0].api.clone();
    let witness_full = nodes[1].api.clone();
    let requester_agua = nodes[2].api.clone();
    let requester_hash = nodes[3].api.clone();
    let requester_vidrio = nodes[4].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![
            &witness_full,
            &requester_agua,
            &requester_hash,
            &requester_vidrio,
        ],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessFull",
                    "key": witness_full.public_key()
                },
                {
                    "name": "RequesterAgua",
                    "key": requester_agua.public_key()
                },
                {
                    "name": "RequesterHash",
                    "key": requester_hash.public_key()
                },
                {
                    "name": "RequesterVidrio",
                    "key": requester_vidrio.public_key()
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
                    "viewpoints": ["agua", "basura", "vidrio"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "WitnessFull",
                        "RequesterAgua",
                        "RequesterHash",
                        "RequesterVidrio"
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
                                        "name": "WitnessFull",
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

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_full, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&requester_agua, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&requester_hash, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&requester_vidrio, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

    let (subject_id, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact_viewpoints(
        &owner,
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
        &owner,
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

    emit_fact(
        &owner,
        subject_id.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&witness_full, subject_id.clone(), Some(3), true)
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
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "RequesterAgua",
                                        "viewpoints": ["agua"]
                                    },
                                    {
                                        "name": "RequesterHash",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "RequesterVidrio",
                                        "viewpoints": ["vidrio"]
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

    let _state =
        get_subject(&requester_agua, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    let _state =
        get_subject(&requester_hash, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    let _state =
        get_subject(&requester_vidrio, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

    for requester in [&requester_agua, &requester_hash, &requester_vidrio] {
        requester
            .auth_subject(
                subject_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(&witness_full.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        requester.update_subject(subject_id.clone()).await.unwrap();
    }

    let agua_state =
        get_subject(&requester_agua, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    let hash_state =
        get_subject(&requester_hash, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    let vidrio_state =
        get_subject(&requester_vidrio, subject_id.clone(), Some(3), true)
            .await
            .unwrap();

    assert_eq!(
        agua_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        hash_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        vidrio_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );

    assert_tracker_visibility(
        &agua_state,
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
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();

    for state in [&hash_state, &vidrio_state] {
        assert_tracker_visibility(
            state,
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
                    visibility: TrackerStoredVisibilityDB::Full,
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
                        viewpoints: vec![],
                    },
                },
            ],
        )
        .unwrap();
    }

    let agua_events = get_events(&requester_agua, subject_id.clone(), 4, true)
        .await
        .unwrap();
    let hash_events = get_events(&requester_hash, subject_id.clone(), 4, true)
        .await
        .unwrap();
    let vidrio_events =
        get_events(&requester_vidrio, subject_id.clone(), 4, true)
            .await
            .unwrap();

    assert_tracker_fact_full(
        &agua_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_opaque(&agua_events[2].event, &["basura"]).unwrap();
    assert_tracker_fact_full(
        &agua_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );

    for events in [&hash_events, &vidrio_events] {
        assert_tracker_fact_opaque(&events[1].event, &["agua"]).unwrap();
        assert_tracker_fact_opaque(&events[2].event, &["basura"]).unwrap();
        assert_tracker_fact_full(
            &events[3].event,
            json!({
                "ModThree": {
                    "data": 3
                }
            }),
            &[],
        );
    }
}

#[test(tokio::test)]
// B06: transferencias que sobreescriben el pasado
//
// Setup:
//   crear facts;
//   después hacer `Transfer`;
//   en otro caso, hacer `Transfer + Confirm`.
//
// Acción:
//   pedir un rango anterior a la transferencia desde el `new_owner`.
//
// Comprobar:
//   el `new_owner` ve en claro ese histórico;
//   tras `Confirm` lo sigue viendo;
//   si hay varias transferencias, manda la última aplicable.
async fn test_viewpoints_transfer_override_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = &nodes[0].api;
    let witness_full = &nodes[1].api;
    let new_owner = &nodes[2].api;
    let final_owner = &nodes[3].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![witness_full, new_owner, final_owner],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessFull",
                    "key": witness_full.public_key()
                },
                {
                    "name": "NewOwner",
                    "key": new_owner.public_key()
                },
                {
                    "name": "FinalOwner",
                    "key": final_owner.public_key()
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
                        "WitnessFull",
                        "NewOwner",
                        "FinalOwner"
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
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ]
                            },
                            {
                                "name": "NewOwner",
                                "namespace": [],
                                "quantity": "infinity",
                            },
                            {
                                "name": "FinalOwner",
                                "namespace": [],
                                "quantity": "infinity",
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

    let _state =
        get_subject(witness_full, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state = get_subject(new_owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let _state = get_subject(final_owner, governance_id.clone(), Some(1), true)
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

    let _state = get_subject(witness_full, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    emit_transfer(
        owner,
        subject_id.clone(),
        PublicKey::from_str(&new_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let pending_state =
        get_subject(new_owner, subject_id.clone(), Some(3), true)
            .await
            .unwrap();

    assert_eq!(
        pending_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &pending_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    let pending_events = get_events(new_owner, subject_id.clone(), 4, true)
        .await
        .unwrap();
    assert_tracker_fact_full(
        &pending_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &pending_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["basura"],
    );

    emit_confirm(new_owner, subject_id.clone(), None, true)
        .await
        .unwrap();

    let confirmed_state =
        get_subject(new_owner, subject_id.clone(), Some(4), true)
            .await
            .unwrap();
    assert_eq!(
        confirmed_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &confirmed_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    let confirmed_events = get_events(new_owner, subject_id.clone(), 5, true)
        .await
        .unwrap();
    assert_tracker_fact_full(
        &confirmed_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &confirmed_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["basura"],
    );

    emit_transfer(
        new_owner,
        subject_id.clone(),
        PublicKey::from_str(&final_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    final_owner
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_full.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    final_owner
        .update_subject(subject_id.clone())
        .await
        .unwrap();

    let final_state =
        get_subject(final_owner, subject_id.clone(), Some(5), true)
            .await
            .unwrap();
    assert_eq!(
        final_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &final_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    let final_events = get_events(final_owner, subject_id.clone(), 6, true)
        .await
        .unwrap();
    assert_tracker_fact_full(
        &final_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &final_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["basura"],
    );
}

#[test(tokio::test)]
// B07: `Reject`, `old_owner` y ownership repetido
//
// Setup:
//   crear facts;
//   hacer `Transfer + Reject`;
//   en otros casos, encadenar varias transferencias y confirms.
//   añadir un witness que solo tenga viewpoints inválidos para ese histórico.
//
// Acción:
//   pedir histórico como `new_owner` rechazado y como `old_owner`.
//
// Comprobar:
//   el rechazo corta donde toca;
//   `old_owner` no ve por encima de su `sn`;
//   si hay varios cortes, se usa el más alto válido.
//   un witness sin viewpoints válidos no gana claridad por haber sido witness.
async fn test_viewpoints_reject_and_old_owner_battery() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = nodes[0].api.clone();
    let witness_full = nodes[1].api.clone();
    let rejected_owner = nodes[2].api.clone();
    let final_owner = nodes[3].api.clone();
    let invalid_witness = nodes[4].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![
            &witness_full,
            &rejected_owner,
            &final_owner,
            &invalid_witness,
        ],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessFull",
                    "key": witness_full.public_key()
                },
                {
                    "name": "RejectedOwner",
                    "key": rejected_owner.public_key()
                },
                {
                    "name": "FinalOwner",
                    "key": final_owner.public_key()
                },
                {
                    "name": "InvalidWitness",
                    "key": invalid_witness.public_key()
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
                    "viewpoints": ["agua", "basura", "vidrio"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "WitnessFull",
                        "RejectedOwner",
                        "FinalOwner",
                        "InvalidWitness"
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
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "InvalidWitness",
                                        "viewpoints": ["vidrio"]
                                    }
                                ]
                            },
                            {
                                "name": "RejectedOwner",
                                "namespace": [],
                                "quantity": "infinity",
                            },
                            {
                                "name": "FinalOwner",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
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

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_full, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&rejected_owner, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&final_owner, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&invalid_witness, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

    let (subject_id, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact_viewpoints(
        &owner,
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
        &owner,
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

    let _state = get_subject(&witness_full, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    emit_transfer(
        &owner,
        subject_id.clone(),
        PublicKey::from_str(&rejected_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let pending_state =
        get_subject(&rejected_owner, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(
        pending_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &pending_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    emit_reject(&rejected_owner, subject_id.clone(), true)
        .await
        .unwrap();

    let rejected_state =
        get_subject(&rejected_owner, subject_id.clone(), Some(4), true)
            .await
            .unwrap();
    assert_eq!(
        rejected_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &rejected_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    emit_fact(
        &owner,
        subject_id.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        true,
    )
    .await
    .unwrap();

    emit_fact_viewpoints(
        &owner,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 4
            }
        }),
        BTreeSet::from(["agua".to_owned()]),
        true,
    )
    .await
    .unwrap();

    emit_transfer(
        &owner,
        subject_id.clone(),
        PublicKey::from_str(&final_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&final_owner, subject_id.clone(), Some(7), true)
        .await
        .unwrap();

    emit_confirm(&final_owner, subject_id.clone(), None, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_full, subject_id.clone(), Some(8), true)
        .await
        .unwrap();

    let final_state =
        get_subject(&final_owner, subject_id.clone(), Some(8), true)
            .await
            .unwrap();
    assert_eq!(
        final_state.properties,
        json!({
            "one": 4,
            "two": 2,
            "three": 3
        })
    );
    assert_tracker_visibility(
        &final_state,
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
                to_sn: Some(5),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 6,
                to_sn: Some(6),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 7,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                to_sn: Some(4),
                visibility: TrackerEventVisibilityDB::NonFact,
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 5,
                to_sn: Some(5),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 6,
                to_sn: Some(6),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 7,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    nodes[2].token.cancel();
    join_all(nodes[2].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (old_rejected_node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
    .await;
    let old_rejected = old_rejected_node.api;
    node_running(&old_rejected).await.unwrap();

    old_rejected
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    old_rejected
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _state =
        get_subject(&old_rejected, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

    old_rejected
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_full.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    old_rejected
        .update_subject(subject_id.clone())
        .await
        .unwrap();

    let old_rejected_state =
        get_subject(&old_rejected, subject_id.clone(), Some(4), true)
            .await
            .unwrap();
    assert_eq!(
        old_rejected_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &old_rejected_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();
    let old_rejected_events =
        get_events(&old_rejected, subject_id.clone(), 5, true)
            .await
            .unwrap();
    assert_tracker_fact_full(
        &old_rejected_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &old_rejected_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["basura"],
    );

    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let peers = vec![RoutingNode {
        peer_id: witness_full.peer_id().to_string(),
        address: vec![nodes[1].listen_address.clone()],
    }];

    let owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let owner_listen_address = format!("/memory/{}", owner_port);
    let (old_owner_node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: owner_listen_address,
        peers,
        always_accept: true,
        keys: Some(nodes[0].keys.clone()),
        ..Default::default()
    })
    .await;
    let old_owner = old_owner_node.api;
    node_running(&old_owner).await.unwrap();

    old_owner
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_full.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    old_owner
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _state = get_subject(&old_owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    old_owner
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_full.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    old_owner.update_subject(subject_id.clone()).await.unwrap();

    let old_owner_state =
        get_subject(&old_owner, subject_id.clone(), Some(8), true)
            .await
            .unwrap();
    assert_eq!(
        old_owner_state.properties,
        json!({
            "one": 4,
            "two": 2,
            "three": 3
        })
    );
    assert_tracker_visibility(
        &old_owner_state,
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
                to_sn: Some(5),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 6,
                to_sn: Some(6),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 7,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                to_sn: Some(4),
                visibility: TrackerEventVisibilityDB::NonFact,
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 5,
                to_sn: Some(5),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 6,
                to_sn: Some(6),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 7,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    invalid_witness
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_full.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    invalid_witness
        .update_subject(subject_id.clone())
        .await
        .unwrap();

    let invalid_state =
        get_subject(&invalid_witness, subject_id.clone(), Some(8), true)
            .await
            .unwrap();
    assert_eq!(
        invalid_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &invalid_state,
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
                to_sn: Some(5),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 6,
                to_sn: Some(6),
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 7,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                to_sn: Some(4),
                visibility: TrackerEventVisibilityDB::NonFact,
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 5,
                to_sn: Some(5),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 6,
                to_sn: Some(6),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 7,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    let invalid_events =
        get_events(&invalid_witness, subject_id.clone(), 9, true)
            .await
            .unwrap();
    assert_tracker_fact_opaque(&invalid_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_opaque(&invalid_events[2].event, &["basura"]).unwrap();
    assert_tracker_fact_full(
        &invalid_events[5].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );
    assert_tracker_fact_opaque(&invalid_events[6].event, &["agua"]).unwrap();
}

#[test(tokio::test)]
// B08: proyección `TrackerFactFull -> TrackerFactOpaque`
//
// Setup:
//   crear facts full;
//   preparar un nodo con acceso full y otro con acceso solo hash.
//   añadir facts con viewpoints inexistentes para ese requester.
//
// Acción:
//   pedir batches en claro, opacos y mixtos.
//
// Comprobar:
//   la proyección opaque es la canónica;
//   un nodo parcial no puede servir `Clear`;
//   un batch mixto sale con el orden correcto.
//   un fact sin viewpoint válido para el requester sale opaco aunque exista en full.
//   `Transfer`, `Confirm`, `Reject` y `EOL` siguen saliendo en claro.
async fn test_viewpoints_projection_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = nodes[0].api.clone();
    let witness_full = nodes[1].api.clone();
    let sender_agua = nodes[2].api.clone();
    let new_owner = nodes[3].api.clone();
    let requester_basura = nodes[4].api.clone();
    let requester_hash = nodes[5].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![
            &witness_full,
            &sender_agua,
            &new_owner,
            &nodes[4].api,
            &nodes[5].api,
        ],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessFull",
                    "key": witness_full.public_key()
                },
                {
                    "name": "SenderAgua",
                    "key": sender_agua.public_key()
                },
                {
                    "name": "NewOwner",
                    "key": new_owner.public_key()
                },
                {
                    "name": "RequesterBasura",
                    "key": nodes[4].api.public_key()
                },
                {
                    "name": "RequesterHash",
                    "key": nodes[5].api.public_key()
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
                        "WitnessFull",
                        "SenderAgua",
                        "NewOwner",
                        "RequesterBasura",
                        "RequesterHash"
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
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "SenderAgua",
                                        "viewpoints": ["agua"]
                                    }
                                ]
                            },
                            {
                                "name": "NewOwner",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "SenderAgua",
                                        "viewpoints": ["agua"]
                                    }
                                ]
                            }
                        ],
                        "issuer": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "NewOwner",
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
        get_subject(&witness_full, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&sender_agua, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state = get_subject(&new_owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let _state =
        get_subject(&requester_basura, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&requester_hash, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

    let (subject_id, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact_viewpoints(
        &owner,
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
        &owner,
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

    emit_fact(
        &owner,
        subject_id.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&witness_full, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let _state = get_subject(&sender_agua, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    emit_transfer(
        &owner,
        subject_id.clone(),
        PublicKey::from_str(&new_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&new_owner, subject_id.clone(), Some(4), true)
        .await
        .unwrap();

    emit_reject(&new_owner, subject_id.clone(), true)
        .await
        .unwrap();

    emit_transfer(
        &owner,
        subject_id.clone(),
        PublicKey::from_str(&new_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    emit_confirm(&new_owner, subject_id.clone(), None, true)
        .await
        .unwrap();

    let _state = get_subject(&new_owner, subject_id.clone(), Some(7), true)
        .await
        .unwrap();

    emit_eol(&new_owner, subject_id.clone(), true)
        .await
        .unwrap();

    let _state = get_subject(&witness_full, subject_id.clone(), Some(8), true)
        .await
        .unwrap();
    let _state = get_subject(&sender_agua, subject_id.clone(), Some(8), true)
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
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "SenderAgua",
                                        "viewpoints": ["agua"]
                                    },
                                    {
                                        "name": "RequesterBasura",
                                        "viewpoints": ["basura"]
                                    },
                                    {
                                        "name": "RequesterHash",
                                        "viewpoints": []
                                    }
                                ]
                            },
                            {
                                "actual_name": "NewOwner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "SenderAgua",
                                        "viewpoints": ["agua"]
                                    },
                                    {
                                        "name": "RequesterBasura",
                                        "viewpoints": ["basura"]
                                    },
                                    {
                                        "name": "RequesterHash",
                                        "viewpoints": []
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

    let _state =
        get_subject(&requester_basura, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    let _state =
        get_subject(&requester_hash, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

    requester_basura
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&sender_agua.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    requester_basura
        .update_subject(subject_id.clone())
        .await
        .unwrap();

    let basura_state =
        get_subject(&requester_basura, subject_id.clone(), Some(8), true)
            .await
            .unwrap();
    assert_eq!(
        basura_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &basura_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                to_sn: Some(3),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 4,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    let basura_events =
        get_events(&requester_basura, subject_id.clone(), 9, true)
            .await
            .unwrap();
    assert_tracker_fact_opaque(&basura_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_opaque(&basura_events[2].event, &["basura"]).unwrap();
    assert_tracker_fact_full(
        &basura_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );
    assert!(matches!(
        basura_events[4].event,
        RequestEventDB::Transfer { .. }
    ));
    assert!(matches!(basura_events[5].event, RequestEventDB::Reject));
    assert!(matches!(
        basura_events[6].event,
        RequestEventDB::Transfer { .. }
    ));
    assert!(matches!(
        basura_events[7].event,
        RequestEventDB::TrackerConfirm
    ));
    assert!(matches!(basura_events[8].event, RequestEventDB::EOL));

    requester_hash
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_full.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    requester_hash
        .update_subject(subject_id.clone())
        .await
        .unwrap();

    let hash_state =
        get_subject(&requester_hash, subject_id.clone(), Some(8), true)
            .await
            .unwrap();
    assert_eq!(
        hash_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &hash_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                to_sn: Some(3),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 4,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::NonFact,
            },
        ],
    )
    .unwrap();

    let hash_events = get_events(&requester_hash, subject_id.clone(), 9, true)
        .await
        .unwrap();
    assert_tracker_fact_opaque(&hash_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_opaque(&hash_events[2].event, &["basura"]).unwrap();
    assert_tracker_fact_full(
        &hash_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );
    assert!(matches!(
        hash_events[4].event,
        RequestEventDB::Transfer { .. }
    ));
    assert!(matches!(hash_events[5].event, RequestEventDB::Reject));
    assert!(matches!(
        hash_events[6].event,
        RequestEventDB::Transfer { .. }
    ));
    assert!(matches!(
        hash_events[7].event,
        RequestEventDB::TrackerConfirm
    ));
    assert!(matches!(hash_events[8].event, RequestEventDB::EOL));
}

#[test(tokio::test)]
// B09: copia manual, auth y auto-update
//
// Setup:
//   usar el mismo requester y los mismos witnesses para las tres rutas.
//   incluir un requester sin viewpoints válidos y otro con viewpoints parciales.
//
// Acción:
//   ejecutar manual distribution, auth update y auto-update sobre el mismo caso.
//
// Comprobar:
//   las tres rutas devuelven la misma claridad;
//   manual no abre más de lo debido;
//   si hay gap, el catch-up va primero al mismo sender.
//   si el requester no tiene viewpoints válidos, las tres rutas devuelven opaco igual.
//   si el sender local solo almacena opaque, no puede servir `Clear` aunque el requester lo merezca teóricamente.
async fn test_viewpoints_copy_paths_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![
                vec![0],
                vec![0],
                vec![0],
                vec![0],
                vec![0],
                vec![0],
                vec![0],
            ],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = nodes[0].api.clone();
    let sender_agua = nodes[1].api.clone();
    let requester_manual = nodes[2].api.clone();
    let requester_auth = nodes[3].api.clone();
    let requester_auto = nodes[4].api.clone();
    let invalid_manual = nodes[5].api.clone();
    let invalid_auth = nodes[6].api.clone();
    let invalid_auto = nodes[7].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![
            &sender_agua,
            &requester_manual,
            &requester_auth,
            &requester_auto,
            &invalid_manual,
            &invalid_auth,
            &invalid_auto,
        ],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "SenderAgua",
                    "key": sender_agua.public_key()
                },
                {
                    "name": "RequesterManual",
                    "key": requester_manual.public_key()
                },
                {
                    "name": "RequesterAuth",
                    "key": requester_auth.public_key()
                },
                {
                    "name": "RequesterAuto",
                    "key": requester_auto.public_key()
                },
                {
                    "name": "InvalidManual",
                    "key": invalid_manual.public_key()
                },
                {
                    "name": "InvalidAuth",
                    "key": invalid_auth.public_key()
                },
                {
                    "name": "InvalidAuto",
                    "key": invalid_auto.public_key()
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
                    "viewpoints": ["agua", "basura", "vidrio"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "SenderAgua",
                        "RequesterManual",
                        "RequesterAuth",
                        "RequesterAuto",
                        "InvalidManual",
                        "InvalidAuth",
                        "InvalidAuto"
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
                                        "name": "SenderAgua",
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

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    for node in [
        &sender_agua,
        &requester_manual,
        &requester_auth,
        &requester_auto,
        &invalid_manual,
        &invalid_auth,
        &invalid_auto,
    ] {
        let _ = get_subject(node, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    let (subject_manual, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let (subject_auth, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let (subject_auto, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for subject_id in [
        subject_manual.clone(),
        subject_auth.clone(),
        subject_auto.clone(),
    ] {
        emit_fact_viewpoints(
            &owner,
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
            &owner,
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

        emit_fact(
            &owner,
            subject_id.clone(),
            json!({
                "ModThree": {
                    "data": 3
                }
            }),
            true,
        )
        .await
        .unwrap();
    }

    for subject_id in [
        subject_manual.clone(),
        subject_auth.clone(),
        subject_auto.clone(),
    ] {
        let _ = get_subject(&sender_agua, subject_id, Some(3), true)
            .await
            .unwrap();
    }

    for (node, subject_id) in [
        (&requester_manual, subject_manual.clone()),
        (&invalid_manual, subject_manual.clone()),
        (&requester_auth, subject_auth.clone()),
        (&invalid_auth, subject_auth.clone()),
        (&requester_auto, subject_auto.clone()),
        (&invalid_auto, subject_auto.clone()),
    ] {
        assert!(node.get_subject_state(subject_id).await.is_err());
    }

    let json = json!({
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
                                        "name": "SenderAgua",
                                        "viewpoints": ["agua"]
                                    },
                                    {
                                        "name": "RequesterManual",
                                        "viewpoints": ["basura"]
                                    },
                                    {
                                        "name": "RequesterAuth",
                                        "viewpoints": ["basura"]
                                    },
                                    {
                                        "name": "RequesterAuto",
                                        "viewpoints": ["basura"]
                                    },
                                    {
                                        "name": "InvalidManual",
                                        "viewpoints": ["vidrio"]
                                    },
                                    {
                                        "name": "InvalidAuth",
                                        "viewpoints": ["vidrio"]
                                    },
                                    {
                                        "name": "InvalidAuto",
                                        "viewpoints": ["vidrio"]
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

    for node in [
        &requester_manual,
        &requester_auth,
        &requester_auto,
        &invalid_manual,
        &invalid_auth,
        &invalid_auto,
    ] {
        let _ = get_subject(node, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    owner
        .manual_distribution(subject_manual.clone())
        .await
        .unwrap();

    requester_auth
        .auth_subject(
            subject_auth.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    requester_auth
        .update_subject(subject_auth.clone())
        .await
        .unwrap();

    invalid_auth
        .auth_subject(
            subject_auth.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    invalid_auth
        .update_subject(subject_auth.clone())
        .await
        .unwrap();

    emit_fact(
        &owner,
        subject_auto.clone(),
        json!({
            "ModThree": {
                "data": 4
            }
        }),
        true,
    )
    .await
    .unwrap();

    let _ = get_subject(&owner, subject_auto.clone(), Some(4), true)
        .await
        .unwrap();

    let manual_state =
        get_subject(&requester_manual, subject_manual.clone(), Some(3), true)
            .await
            .unwrap();
    let auth_state =
        get_subject(&requester_auth, subject_auth.clone(), Some(3), true)
            .await
            .unwrap();
    let auto_state =
        get_subject(&requester_auto, subject_auto.clone(), Some(4), true)
            .await
            .unwrap();
    let invalid_manual_state =
        get_subject(&invalid_manual, subject_manual.clone(), Some(3), true)
            .await
            .unwrap();
    let invalid_auth_state =
        get_subject(&invalid_auth, subject_auth.clone(), Some(3), true)
            .await
            .unwrap();
    let invalid_auto_state =
        get_subject(&invalid_auto, subject_auto.clone(), Some(4), true)
            .await
            .unwrap();

    let expected_properties = json!({
        "one": 0,
        "two": 0,
        "three": 0
    });

    for state in [
        &manual_state,
        &auth_state,
        &auto_state,
        &invalid_manual_state,
        &invalid_auth_state,
        &invalid_auto_state,
    ] {
        assert_eq!(state.properties, expected_properties);
    }

    for state in [&invalid_manual_state, &invalid_auth_state] {
        assert_tracker_visibility(
            state,
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
                    visibility: TrackerStoredVisibilityDB::Full,
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
                        viewpoints: vec![],
                    },
                },
            ],
        )
        .unwrap();
    }

    for state in [&manual_state, &auth_state] {
        assert_tracker_visibility(
            state,
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
                    visibility: TrackerStoredVisibilityDB::None,
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
                    visibility: TrackerStoredVisibilityDB::Full,
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
                        viewpoints: vec![],
                    },
                },
            ],
        )
        .unwrap();
    }

    assert_tracker_visibility(
        &auto_state,
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
                visibility: TrackerStoredVisibilityDB::None,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();

    assert_tracker_visibility(
        &invalid_auto_state,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();

    let manual_events =
        get_events(&requester_manual, subject_manual.clone(), 4, true)
            .await
            .unwrap();
    let auth_events =
        get_events(&requester_auth, subject_auth.clone(), 4, true)
            .await
            .unwrap();
    let auto_events =
        get_events(&requester_auto, subject_auto.clone(), 5, true)
            .await
            .unwrap();
    let invalid_manual_events =
        get_events(&invalid_manual, subject_manual.clone(), 4, true)
            .await
            .unwrap();
    let invalid_auth_events =
        get_events(&invalid_auth, subject_auth.clone(), 4, true)
            .await
            .unwrap();
    let invalid_auto_events =
        get_events(&invalid_auto, subject_auto.clone(), 5, true)
            .await
            .unwrap();

    for events in [&invalid_manual_events, &invalid_auth_events] {
        assert_tracker_fact_opaque(&events[1].event, &["agua"]).unwrap();
        assert_tracker_fact_opaque(&events[2].event, &["basura"]).unwrap();
        assert_tracker_fact_full(
            &events[3].event,
            json!({
                "ModThree": {
                    "data": 3
                }
            }),
            &[],
        );
    }

    for events in [&manual_events, &auth_events] {
        assert_tracker_fact_opaque(&events[1].event, &["agua"]).unwrap();
        assert_tracker_fact_full(
            &events[2].event,
            json!({
                "ModTwo": {
                    "data": 2
                }
            }),
            &["basura"],
        );
        assert_tracker_fact_full(
            &events[3].event,
            json!({
                "ModThree": {
                    "data": 3
                }
            }),
            &[],
        );
    }

    assert_tracker_fact_opaque(&invalid_auto_events[1].event, &["agua"])
        .unwrap();
    assert_tracker_fact_opaque(&invalid_auto_events[2].event, &["basura"])
        .unwrap();
    assert_tracker_fact_full(
        &invalid_auto_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );
    assert_tracker_fact_full(
        &invalid_auto_events[4].event,
        json!({
            "ModThree": {
                "data": 4
            }
        }),
        &[],
    );

    assert_tracker_fact_opaque(&auto_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_full(
        &auto_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["basura"],
    );
    assert_tracker_fact_full(
        &auto_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );
    assert_tracker_fact_full(
        &auto_events[4].event,
        json!({
            "ModThree": {
                "data": 4
            }
        }),
        &[],
    );
}

#[test(tokio::test)]
// B10: mezclas extremas
//
// Setup:
//   mezclar grants genéricos y explícitos;
//   mezclar namespace;
//   mezclar ownership repetido y facts con distintos viewpoints.
//   meter también viewpoints inexistentes, repetidos o irrelevantes.
//
// Acción:
//   pedir un batch largo con varios cambios en medio.
//
// Comprobar:
//   en cada tramo gana el grant correcto;
//   no se abre nada por accidente;
//   un mismo batch puede cambiar de `Hash` a `Full` y volver.
//   viewpoints inexistentes o irrelevantes no alteran el resultado.
//   `Full + Hash + Clear(agua)` sigue resolviendo `Full`.
async fn test_viewpoints_extreme_combinations_battery() {
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

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Witness",
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
                },
                {
                    "id": "Other",
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
                        "Witness"
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
                                        "name": "Witness",
                                        "viewpoints": []
                                    }
                                ]
                            },
                            {
                                "name": "Owner",
                                "namespace": ["Test1"],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "Witness",
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
                },
                {
                    "schema_id": "Other",
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
                                        "name": "Witness",
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

    let (subject_default, ..) =
        create_subject(owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let (subject_namespace, ..) =
        create_subject(owner, governance_id.clone(), "Example", "Test1", true)
            .await
            .unwrap();
    let (subject_other, ..) =
        create_subject(owner, governance_id.clone(), "Other", "", true)
            .await
            .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_default.clone(),
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
    emit_fact(
        owner,
        subject_default.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        true,
    )
    .await
    .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_namespace.clone(),
        json!({
            "ModOne": {
                "data": 10
            }
        }),
        BTreeSet::from(["agua".to_owned()]),
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
                                "actual_name": "Owner",
                                "actual_namespace": ["Test1"],
                                "new_witnesses": [
                                    {
                                        "name": "Witness",
                                        "viewpoints": []
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

    let _ = get_subject(witness, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_namespace.clone(),
        json!({
            "ModTwo": {
                "data": 20
            }
        }),
        BTreeSet::from(["basura".to_owned()]),
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
                                "actual_name": "Owner",
                                "actual_namespace": ["Test1"],
                                "new_witnesses": [
                                    {
                                        "name": "Witness",
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

    let _ = get_subject(witness, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_namespace.clone(),
        json!({
            "ModTwo": {
                "data": 30
            }
        }),
        BTreeSet::from(["basura".to_owned()]),
        true,
    )
    .await
    .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_other.clone(),
        json!({
            "ModOne": {
                "data": 100
            }
        }),
        BTreeSet::from(["agua".to_owned()]),
        true,
    )
    .await
    .unwrap();
    emit_fact_viewpoints(
        owner,
        subject_other.clone(),
        json!({
            "ModTwo": {
                "data": 200
            }
        }),
        BTreeSet::from(["basura".to_owned()]),
        true,
    )
    .await
    .unwrap();

    let default_state =
        get_subject(witness, subject_default.clone(), Some(2), true)
            .await
            .unwrap();
    assert_eq!(
        default_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &default_state,
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
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 2,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();

    let namespace_state =
        get_subject(witness, subject_namespace.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(
        namespace_state.properties,
        json!({
            "one": 10,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &namespace_state,
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
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["basura".to_owned()],
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let other_state =
        get_subject(witness, subject_other.clone(), Some(2), true)
            .await
            .unwrap();
    assert_eq!(
        other_state.properties,
        json!({
            "one": 100,
            "two": 200,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &other_state,
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
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["basura".to_owned()],
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let default_events = get_events(witness, subject_default.clone(), 3, true)
        .await
        .unwrap();
    assert_tracker_fact_opaque(&default_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_full(
        &default_events[2].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );

    let namespace_events =
        get_events(witness, subject_namespace.clone(), 4, true)
            .await
            .unwrap();
    assert_tracker_fact_full(
        &namespace_events[1].event,
        json!({
            "ModOne": {
                "data": 10
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_opaque(&namespace_events[2].event, &["basura"])
        .unwrap();
    assert_tracker_fact_full(
        &namespace_events[3].event,
        json!({
            "ModTwo": {
                "data": 30
            }
        }),
        &["basura"],
    );

    let other_events = get_events(witness, subject_other.clone(), 3, true)
        .await
        .unwrap();
    assert_tracker_fact_full(
        &other_events[1].event,
        json!({
            "ModOne": {
                "data": 100
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &other_events[2].event,
        json!({
            "ModTwo": {
                "data": 200
            }
        }),
        &["basura"],
    );
}

#[test(tokio::test)]
// B11: planificación multi-tramo con rangos discontinuos
//
// Setup:
//   preparar witnesses con rangos cortados y huecos;
//   añadir otro caso con un witness que cubra todo.
//
// Acción:
//   lanzar update desde un `sn` intermedio.
//
// Comprobar:
//   el plan sale tramo a tramo en el orden esperado;
//   si hay un witness dominante, se usa solo ese;
//   un hueco en el `next_sn` invalida ese witness para ese tramo.
//   si un witness solo cubre el `next_sn` en `Opaque` y otro en `Clear`, gana `Clear`.
async fn test_viewpoints_update_disjoint_ranges_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = &nodes[0].api;
    let clear_short = &nodes[1].api;
    let opaque_mid = &nodes[2].api;
    let future_clear = &nodes[3].api;
    let requester = &nodes[4].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![clear_short, opaque_mid, future_clear, requester],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "ClearShort",
                    "key": clear_short.public_key()
                },
                {
                    "name": "OpaqueMid",
                    "key": opaque_mid.public_key()
                },
                {
                    "name": "FutureClear",
                    "key": future_clear.public_key()
                },
                {
                    "name": "Requester",
                    "key": requester.public_key()
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
                    "viewpoints": ["agua"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "ClearShort",
                        "OpaqueMid",
                        "FutureClear",
                        "Requester"
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
                                        "name": "ClearShort",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "OpaqueMid",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "FutureClear",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "Requester",
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

    for node in [clear_short, opaque_mid, future_clear, requester] {
        let _ = get_subject(node, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    let (subject_id, ..) =
        create_subject(owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for data in 1..=4 {
        emit_fact_viewpoints(
            owner,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            BTreeSet::from(["agua".to_owned()]),
            true,
        )
        .await
        .unwrap();
    }

    let _ = get_subject(requester, subject_id.clone(), Some(4), true)
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
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "ClearShort",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "OpaqueMid",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "FutureClear",
                                        "viewpoints": []
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

    for node in [clear_short, opaque_mid, future_clear, requester] {
        let _ = get_subject(node, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    for data in 5..=6 {
        emit_fact_viewpoints(
            owner,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            BTreeSet::from(["agua".to_owned()]),
            true,
        )
        .await
        .unwrap();
    }

    let json = json!({
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
                                        "name": "OpaqueMid",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "FutureClear",
                                        "viewpoints": []
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

    for node in [opaque_mid, future_clear, requester] {
        let _ = get_subject(node, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
    }

    for data in 7..=8 {
        emit_fact_viewpoints(
            owner,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            BTreeSet::from(["agua".to_owned()]),
            true,
        )
        .await
        .unwrap();
    }

    let json = json!({
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
                                        "name": "FutureClear",
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

    for node in [future_clear, requester] {
        let _ = get_subject(node, governance_id.clone(), Some(4), true)
            .await
            .unwrap();
    }

    for data in 9..=12 {
        emit_fact_viewpoints(
            owner,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            BTreeSet::from(["agua".to_owned()]),
            true,
        )
        .await
        .unwrap();
    }

    let json = json!({
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
                                        "name": "FutureClear",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "Requester",
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

    let _ = get_subject(requester, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    let clear_short_state =
        get_subject(clear_short, subject_id.clone(), Some(6), true)
            .await
            .unwrap();
    let opaque_mid_state =
        get_subject(opaque_mid, subject_id.clone(), Some(8), true)
            .await
            .unwrap();
    let future_clear_state =
        get_subject(future_clear, subject_id.clone(), Some(12), true)
            .await
            .unwrap();

    assert_eq!(
        clear_short_state.properties,
        json!({
            "one": 6,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        opaque_mid_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        future_clear_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );

    requester
        .auth_subject(
            subject_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(&clear_short.public_key()).unwrap(),
                PublicKey::from_str(&opaque_mid.public_key()).unwrap(),
                PublicKey::from_str(&future_clear.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();
    requester.update_subject(subject_id.clone()).await.unwrap();

    let requester_state =
        get_subject(requester, subject_id.clone(), Some(12), true)
            .await
            .unwrap();
    assert_eq!(
        requester_state.properties,
        json!({
            "one": 6,
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
                to_sn: Some(6),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 7,
                to_sn: Some(8),
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 9,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let events = get_events(requester, subject_id.clone(), 13, true)
        .await
        .unwrap();

    for data in 1..=6 {
        assert_tracker_fact_full(
            &events[data as usize].event,
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            &["agua"],
        );
    }

    for data in 7..=8 {
        assert_tracker_fact_opaque(&events[data as usize].event, &["agua"])
            .unwrap();
    }

    for data in 9..=12 {
        assert_tracker_fact_full(
            &events[data as usize].event,
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            &["agua"],
        );
    }
}

#[test(tokio::test)]
// B12: validación de inputs de viewpoints y grants
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
// B13: cambios de viewpoints del schema y copias de viewpoints obsoletos
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
// B14: varios cambios de schema y supervivencia parcial de grants
//
// Setup:
//   crear un schema con `agua`, `basura` y `vidrio`;
//   dar a `Alice` los viewpoints `agua` y `vidrio`;
//   emitir facts con `agua` y `vidrio`;
//   cambiar el schema a `vidrio` y `papel`.
//
// Acción:
//   comprobar que `Alice` se adapta a `vidrio`;
//   rechazar un fact nuevo con `agua`;
//   emitir nuevos facts con `vidrio` y `papel`;
//   arrancar a `Alice` desde 0 y pedir copia completa.
//
// Comprobar:
//   `Alice` conserva en claro el histórico de `agua` y `vidrio`;
//   el nuevo `papel` llega opaco;
//   el grant adaptado conserva solo el subconjunto superviviente.
async fn test_viewpoints_schema_subset_survival_battery() {
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

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessNode",
                    "key": witness.public_key()
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
                    "viewpoints": ["agua", "basura", "vidrio"]
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
                                        "viewpoints": ["agua", "vidrio"]
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
        BTreeSet::from(["vidrio".to_owned()]),
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_viewpoints": ["vidrio", "papel"]
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
        BTreeSet::from(["papel".to_owned(), "vidrio".to_owned()])
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
                viewpoints: BTreeSet::from(["vidrio".to_owned()]),
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

    emit_fact_viewpoints(
        owner,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 4
            }
        }),
        BTreeSet::from(["papel".to_owned()]),
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
    let _ = get_subject(&alice_node.api, governance_id.clone(), Some(2), true)
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

    let alice_state =
        get_subject(&alice_node.api, subject_id.clone(), Some(4), true)
            .await
            .unwrap();
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
                to_sn: Some(3),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["vidrio".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 4,
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
                to_sn: Some(3),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["vidrio".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 4,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["papel".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let alice_events = get_events(&alice_node.api, subject_id.clone(), 5, true)
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
    assert_tracker_fact_full(
        &alice_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["vidrio"],
    );
    assert_tracker_fact_full(
        &alice_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &["vidrio"],
    );
    assert_tracker_fact_opaque(&alice_events[4].event, &["papel"]).unwrap();
}

#[test(tokio::test)]
// B15: transiciones `viewpoints -> [] -> viewpoints`
//
// Setup:
//   crear un schema con `agua`;
//   dar a `Alice` el viewpoint `agua`;
//   emitir un fact con `agua`;
//   quitar todos los viewpoints del schema y luego añadir `papel`.
//
// Acción:
//   comprobar que `Alice` se adapta a `[]` tras quitar `agua`;
//   emitir un fact sin viewpoints mientras el schema está vacío;
//   reintroducir un viewpoint nuevo `papel`;
//   arrancar a `Alice` desde 0 y pedir copia completa.
//
// Comprobar:
//   `Alice` conserva `agua` histórico en claro;
//   el fact sin viewpoints llega en claro;
//   el viewpoint reintroducido después llega opaco.
async fn test_viewpoints_schema_empty_roundtrip_battery() {
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

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessNode",
                    "key": witness.public_key()
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
                    "viewpoints": ["agua"]
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

    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_viewpoints": []
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
        BTreeSet::new()
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

    emit_fact(
        owner,
        subject_id.clone(),
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_viewpoints": ["papel"]
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
    assert_eq!(
        governance.schemas.get(&schema_id).unwrap().viewpoints,
        BTreeSet::from(["papel".to_owned()])
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

    emit_fact_viewpoints(
        owner,
        subject_id.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        BTreeSet::from(["papel".to_owned()]),
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

    let alice_state =
        get_subject(&alice_node.api, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
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
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
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
                    viewpoints: vec![],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["papel".to_owned()],
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
    assert_tracker_fact_full(
        &alice_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &[],
    );
    assert_tracker_fact_opaque(&alice_events[3].event, &["papel"]).unwrap();
}

#[test(tokio::test)]
// B16: grants ligados al creator con mismo schema y mismo witness
//
// Setup:
//   crear dos creators con el mismo schema y namespace;
//   usar el mismo witness para ambos creators;
//   dar al witness `agua` para `CreatorA` y `basura` para `CreatorB`.
//
// Acción:
//   crear dos subjects, uno por creator;
//   emitir el mismo patrón de facts (`agua`, `basura` y un fact sin viewpoints)
//   en ambos subjects.
//
// Comprobar:
//   el grant de `CreatorA` no se arrastra al subject de `CreatorB`;
//   el witness solo ve en claro el tramo que autoriza el creator correcto;
//   el mismo schema y namespace no mezclan grants entre creators.
async fn test_viewpoints_creator_change_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let witness = &nodes[1].api;
    let creator_a = &nodes[2].api;
    let creator_b = &nodes[3].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![witness, creator_a, creator_b],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessNode",
                    "key": witness.public_key()
                },
                {
                    "name": "CreatorA",
                    "key": creator_a.public_key()
                },
                {
                    "name": "CreatorB",
                    "key": creator_b.public_key()
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
                                "name": "CreatorA",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "WitnessNode",
                                        "viewpoints": ["agua"]
                                    }
                                ]
                            },
                            {
                                "name": "CreatorB",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "WitnessNode",
                                        "viewpoints": ["basura"]
                                    }
                                ]
                            }
                        ],
                        "issuer": [
                            {
                                "name": "CreatorA",
                                "namespace": []
                            },
                            {
                                "name": "CreatorB",
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
    creator_a
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _ = get_subject(creator_a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    creator_b
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _ = get_subject(creator_b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let governance_state =
        get_subject(owner, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let governance: GovernanceData =
        from_value(governance_state.properties).unwrap();
    let schema_id = SchemaType::Type("Example".to_owned());
    let creators = &governance.roles_schema.get(&schema_id).unwrap().creator;

    assert_eq!(
        creators
            .get(&RoleCreator::create("CreatorA", Namespace::new()))
            .unwrap()
            .witnesses,
        BTreeSet::from([CreatorWitness {
            name: "WitnessNode".to_owned(),
            viewpoints: BTreeSet::from(["agua".to_owned()]),
        }])
    );
    assert_eq!(
        creators
            .get(&RoleCreator::create("CreatorB", Namespace::new()))
            .unwrap()
            .witnesses,
        BTreeSet::from([CreatorWitness {
            name: "WitnessNode".to_owned(),
            viewpoints: BTreeSet::from(["basura".to_owned()]),
        }])
    );

    let (subject_a_id, ..) =
        create_subject(creator_a, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let (subject_b_id, ..) =
        create_subject(creator_b, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact_viewpoints(
        creator_a,
        subject_a_id.clone(),
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
        creator_a,
        subject_a_id.clone(),
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
    emit_fact(
        creator_a,
        subject_a_id.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        true,
    )
    .await
    .unwrap();

    emit_fact_viewpoints(
        creator_b,
        subject_b_id.clone(),
        json!({
            "ModOne": {
                "data": 10
            }
        }),
        BTreeSet::from(["agua".to_owned()]),
        true,
    )
    .await
    .unwrap();
    emit_fact_viewpoints(
        creator_b,
        subject_b_id.clone(),
        json!({
            "ModTwo": {
                "data": 20
            }
        }),
        BTreeSet::from(["basura".to_owned()]),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        creator_b,
        subject_b_id.clone(),
        json!({
            "ModThree": {
                "data": 30
            }
        }),
        true,
    )
    .await
    .unwrap();

    let witness_a_state =
        get_subject(witness, subject_a_id.clone(), Some(3), true)
            .await
            .unwrap();
    let witness_b_state =
        get_subject(witness, subject_b_id.clone(), Some(3), true)
            .await
            .unwrap();

    assert_eq!(
        witness_a_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
        })
    );
    assert_eq!(
        witness_b_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );

    assert_tracker_visibility(
        &witness_a_state,
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
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();

    assert_tracker_visibility(
        &witness_b_state,
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
                visibility: TrackerStoredVisibilityDB::None,
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
                visibility: TrackerStoredVisibilityDB::Full,
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
                    viewpoints: vec![],
                },
            },
        ],
    )
    .unwrap();

    let witness_a_events = get_events(witness, subject_a_id.clone(), 4, true)
        .await
        .unwrap();
    let witness_b_events = get_events(witness, subject_b_id.clone(), 4, true)
        .await
        .unwrap();

    assert_tracker_fact_full(
        &witness_a_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_opaque(&witness_a_events[2].event, &["basura"])
        .unwrap();
    assert_tracker_fact_full(
        &witness_a_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );

    assert_tracker_fact_opaque(&witness_b_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_full(
        &witness_b_events[2].event,
        json!({
            "ModTwo": {
                "data": 20
            }
        }),
        &["basura"],
    );
    assert_tracker_fact_full(
        &witness_b_events[3].event,
        json!({
            "ModThree": {
                "data": 30
            }
        }),
        &[],
    );
}

#[test(tokio::test)]
// B17: `clear_sn`, prefijo contiguo y corte del primer batch
//
// Setup:
//   usar `ledger_batch_size = 3`;
//   repartir un prefijo claro `0..4` entre dos witnesses (`ClearShort` y
//   `ClearLong`);
//   y dejar un tercer witness (`OpaqueNode`) con cola `5..6` en opaque.
//
// Acción:
//   añadir un requester tardío con grant `[]`;
//   autorizarle los tres senders y pedir update desde `our_sn = None`.
//
// Comprobar:
//   el requester termina en `sn = 6` con `0..4` en claro y `5..6` en opaque;
//   el prefijo claro no se corta en `batch_size = 3`;
//   la cola opaca llega después sin perder continuidad.
async fn test_viewpoints_clear_prefix_cut_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(3),
            ..Default::default()
        })
        .await;

    let owner = &nodes[0].api;
    let clear_short = &nodes[1].api;
    let clear_long = &nodes[2].api;
    let opaque = &nodes[3].api;
    let requester = &nodes[4].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![clear_short, clear_long, opaque, requester],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "ClearShort",
                    "key": clear_short.public_key()
                },
                {
                    "name": "ClearLong",
                    "key": clear_long.public_key()
                },
                {
                    "name": "OpaqueNode",
                    "key": opaque.public_key()
                },
                {
                    "name": "Requester",
                    "key": requester.public_key()
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
                    "viewpoints": ["agua"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "ClearShort",
                        "ClearLong",
                        "OpaqueNode",
                        "Requester"
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
                                        "name": "ClearShort",
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

    for node in [clear_short, clear_long, opaque, requester] {
        let _ = get_subject(node, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    let (subject_id, ..) =
        create_subject(owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for data in 1..=2 {
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

    let json = json!({
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
                                        "name": "ClearLong",
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

    for node in [clear_short, clear_long, opaque, requester] {
        let _ = get_subject(node, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    for data in 3..=4 {
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

    let json = json!({
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
                                        "name": "OpaqueNode",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "Requester",
                                        "viewpoints": []
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

    let _ = get_subject(requester, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    for data in 5..=6 {
        emit_fact_viewpoints(
            owner,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            BTreeSet::from(["agua".to_owned()]),
            true,
        )
        .await
        .unwrap();
    }

    requester
        .auth_subject(
            subject_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(&clear_short.public_key()).unwrap(),
                PublicKey::from_str(&clear_long.public_key()).unwrap(),
                PublicKey::from_str(&opaque.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();

    requester.update_subject(subject_id.clone()).await.unwrap();

    let requester_state =
        get_subject(requester, subject_id.clone(), Some(6), true)
            .await
            .unwrap();
    assert_eq!(
        requester_state.properties,
        json!({
            "one": 4,
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
                to_sn: Some(4),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 5,
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
                to_sn: Some(4),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 5,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let events = get_events(requester, subject_id.clone(), 7, true)
        .await
        .unwrap();
    assert_eq!(events.len(), 7);

    for data in 1..=4 {
        assert_tracker_fact_full(
            &events[data as usize].event,
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            &[],
        );
    }

    assert_tracker_fact_opaque(&events[5].event, &["agua"]).unwrap();
    assert_tracker_fact_opaque(&events[6].event, &["agua"]).unwrap();
}

#[test(tokio::test)]
// B18: facts con varios viewpoints en el mismo evento
//
// Setup:
//   crear un schema con `agua`, `basura` y `vidrio`;
//   emitir facts con combinaciones de varios viewpoints;
//   preparar requesters tardíos con grants:
//   solo `agua`, solo `vidrio`, `agua+vidrio`, `agua+basura` y hash.
//
// Acción:
//   actualizar cada requester desde 0 tras emitir todos los facts.
//
// Comprobar:
//   un fact solo sale en claro si todos sus viewpoints están contenidos
//   en el grant del requester;
//   grants parciales no bastan;
//   grants múltiples sí permiten facts con varios viewpoints.
async fn test_viewpoints_multi_viewpoint_fact_battery() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let witness_full = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![witness_full]).await;
    let requester_agua_keys =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let requester_vidrio_keys =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let requester_agua_vidrio_keys =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let requester_agua_basura_keys =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let requester_hash_keys =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessFull",
                    "key": witness_full.public_key()
                },
                {
                    "name": "RequesterAgua",
                    "key": requester_agua_keys.public_key().to_string()
                },
                {
                    "name": "RequesterVidrio",
                    "key": requester_vidrio_keys.public_key().to_string()
                },
                {
                    "name": "RequesterAguaVidrio",
                    "key": requester_agua_vidrio_keys.public_key().to_string()
                },
                {
                    "name": "RequesterAguaBasura",
                    "key": requester_agua_basura_keys.public_key().to_string()
                },
                {
                    "name": "RequesterHash",
                    "key": requester_hash_keys.public_key().to_string()
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
                    "viewpoints": ["agua", "basura", "vidrio"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "WitnessFull"
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
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "RequesterAgua",
                                        "viewpoints": ["agua"]
                                    },
                                    {
                                        "name": "RequesterVidrio",
                                        "viewpoints": ["vidrio"]
                                    },
                                    {
                                        "name": "RequesterAguaVidrio",
                                        "viewpoints": ["agua", "vidrio"]
                                    },
                                    {
                                        "name": "RequesterAguaBasura",
                                        "viewpoints": ["agua", "basura"]
                                    },
                                    {
                                        "name": "RequesterHash",
                                        "viewpoints": []
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

    let _ = get_subject(witness_full, governance_id.clone(), Some(1), true)
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
        BTreeSet::from(["agua".to_owned(), "vidrio".to_owned()]),
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
        BTreeSet::from(["agua".to_owned(), "basura".to_owned()]),
        true,
    )
    .await
    .unwrap();

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

    let requester_agua_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (requester_agua_node, mut requester_agua_dirs) =
        create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{}", requester_agua_port),
            peers: vec![RoutingNode {
                peer_id: owner.peer_id().to_string(),
                address: vec![nodes[0].listen_address.clone()],
            }],
            always_accept: true,
            keys: Some(requester_agua_keys),
            ..Default::default()
        })
        .await;
    dirs.append(&mut requester_agua_dirs);
    node_running(&requester_agua_node.api).await.unwrap();

    let requester_vidrio_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (requester_vidrio_node, mut requester_vidrio_dirs) =
        create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{}", requester_vidrio_port),
            peers: vec![RoutingNode {
                peer_id: owner.peer_id().to_string(),
                address: vec![nodes[0].listen_address.clone()],
            }],
            always_accept: true,
            keys: Some(requester_vidrio_keys),
            ..Default::default()
        })
        .await;
    dirs.append(&mut requester_vidrio_dirs);
    node_running(&requester_vidrio_node.api).await.unwrap();

    let requester_agua_vidrio_port =
        PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (requester_agua_vidrio_node, mut requester_agua_vidrio_dirs) =
        create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{}", requester_agua_vidrio_port),
            peers: vec![RoutingNode {
                peer_id: owner.peer_id().to_string(),
                address: vec![nodes[0].listen_address.clone()],
            }],
            always_accept: true,
            keys: Some(requester_agua_vidrio_keys),
            ..Default::default()
        })
        .await;
    dirs.append(&mut requester_agua_vidrio_dirs);
    node_running(&requester_agua_vidrio_node.api).await.unwrap();

    let requester_agua_basura_port =
        PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (requester_agua_basura_node, mut requester_agua_basura_dirs) =
        create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{}", requester_agua_basura_port),
            peers: vec![RoutingNode {
                peer_id: owner.peer_id().to_string(),
                address: vec![nodes[0].listen_address.clone()],
            }],
            always_accept: true,
            keys: Some(requester_agua_basura_keys),
            ..Default::default()
        })
        .await;
    dirs.append(&mut requester_agua_basura_dirs);
    node_running(&requester_agua_basura_node.api).await.unwrap();

    let requester_hash_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (requester_hash_node, mut requester_hash_dirs) =
        create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{}", requester_hash_port),
            peers: vec![RoutingNode {
                peer_id: owner.peer_id().to_string(),
                address: vec![nodes[0].listen_address.clone()],
            }],
            always_accept: true,
            keys: Some(requester_hash_keys),
            ..Default::default()
        })
        .await;
    dirs.append(&mut requester_hash_dirs);
    node_running(&requester_hash_node.api).await.unwrap();

    for requester in [
        &requester_agua_node.api,
        &requester_vidrio_node.api,
        &requester_agua_vidrio_node.api,
        &requester_agua_basura_node.api,
        &requester_hash_node.api,
    ] {
        requester
            .auth_subject(
                governance_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(&owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        requester
            .update_subject(governance_id.clone())
            .await
            .unwrap();
        let _ = get_subject(requester, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

        requester
            .auth_subject(
                subject_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(&owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        requester.update_subject(subject_id.clone()).await.unwrap();
    }

    let witness_full_state =
        get_subject(witness_full, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(
        witness_full_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 3
        })
    );

    let requester_agua_state = get_subject(
        &requester_agua_node.api,
        subject_id.clone(),
        Some(3),
        true,
    )
    .await
    .unwrap();
    let requester_vidrio_state = get_subject(
        &requester_vidrio_node.api,
        subject_id.clone(),
        Some(3),
        true,
    )
    .await
    .unwrap();
    let requester_agua_vidrio_state = get_subject(
        &requester_agua_vidrio_node.api,
        subject_id.clone(),
        Some(3),
        true,
    )
    .await
    .unwrap();
    let requester_agua_basura_state = get_subject(
        &requester_agua_basura_node.api,
        subject_id.clone(),
        Some(3),
        true,
    )
    .await
    .unwrap();
    let requester_hash_state = get_subject(
        &requester_hash_node.api,
        subject_id.clone(),
        Some(3),
        true,
    )
    .await
    .unwrap();

    assert_tracker_visibility(
        &requester_agua_state,
        TrackerVisibilityModeDB::Opaque,
        vec![
            TrackerStoredVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 1,
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
                    viewpoints: vec!["agua".to_owned(), "vidrio".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned(), "basura".to_owned()],
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

    assert_tracker_visibility(
        &requester_vidrio_state,
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
                    viewpoints: vec!["agua".to_owned(), "vidrio".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned(), "basura".to_owned()],
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

    assert_tracker_visibility(
        &requester_agua_vidrio_state,
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
                    viewpoints: vec!["agua".to_owned(), "vidrio".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 2,
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
                    viewpoints: vec!["agua".to_owned(), "vidrio".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned(), "basura".to_owned()],
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

    assert_tracker_visibility(
        &requester_agua_basura_state,
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
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned(), "basura".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
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
                    viewpoints: vec!["agua".to_owned(), "vidrio".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned(), "basura".to_owned()],
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

    assert_tracker_visibility(
        &requester_hash_state,
        TrackerVisibilityModeDB::Opaque,
        vec![
            TrackerStoredVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 1,
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
                    viewpoints: vec!["agua".to_owned(), "vidrio".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned(), "basura".to_owned()],
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

    let requester_agua_events =
        get_events(&requester_agua_node.api, subject_id.clone(), 4, true)
            .await
            .unwrap();
    assert_tracker_fact_opaque(
        &requester_agua_events[1].event,
        &["agua", "vidrio"],
    )
    .unwrap();
    assert_tracker_fact_opaque(
        &requester_agua_events[2].event,
        &["agua", "basura"],
    )
    .unwrap();
    assert_tracker_fact_opaque(&requester_agua_events[3].event, &["vidrio"])
        .unwrap();

    let requester_vidrio_events =
        get_events(&requester_vidrio_node.api, subject_id.clone(), 4, true)
            .await
            .unwrap();
    assert_tracker_fact_opaque(
        &requester_vidrio_events[1].event,
        &["agua", "vidrio"],
    )
    .unwrap();
    assert_tracker_fact_opaque(
        &requester_vidrio_events[2].event,
        &["agua", "basura"],
    )
    .unwrap();
    assert_tracker_fact_full(
        &requester_vidrio_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &["vidrio"],
    );

    let requester_agua_vidrio_events = get_events(
        &requester_agua_vidrio_node.api,
        subject_id.clone(),
        4,
        true,
    )
    .await
    .unwrap();
    assert_tracker_fact_full(
        &requester_agua_vidrio_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua", "vidrio"],
    );
    assert_tracker_fact_opaque(
        &requester_agua_vidrio_events[2].event,
        &["agua", "basura"],
    )
    .unwrap();
    assert_tracker_fact_full(
        &requester_agua_vidrio_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &["vidrio"],
    );

    let requester_agua_basura_events = get_events(
        &requester_agua_basura_node.api,
        subject_id.clone(),
        4,
        true,
    )
    .await
    .unwrap();
    assert_tracker_fact_opaque(
        &requester_agua_basura_events[1].event,
        &["agua", "vidrio"],
    )
    .unwrap();
    assert_tracker_fact_full(
        &requester_agua_basura_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["agua", "basura"],
    );
    assert_tracker_fact_opaque(
        &requester_agua_basura_events[3].event,
        &["vidrio"],
    )
    .unwrap();

    let requester_hash_events =
        get_events(&requester_hash_node.api, subject_id.clone(), 4, true)
            .await
            .unwrap();
    assert_tracker_fact_opaque(
        &requester_hash_events[1].event,
        &["agua", "vidrio"],
    )
    .unwrap();
    assert_tracker_fact_opaque(
        &requester_hash_events[2].event,
        &["agua", "basura"],
    )
    .unwrap();
    assert_tracker_fact_opaque(&requester_hash_events[3].event, &["vidrio"])
        .unwrap();
}

#[test(tokio::test)]
// B19: restart sin DB, transferencias repetidas y override histórico
//
// Setup:
//   un witness parcial solo ve `agua`;
//   el owner emite facts `agua` y `basura`, así que ese witness mezcla claro y
//   hash;
//   luego se le transfiere el subject a ese witness.
//
// Acción:
//   reiniciar ese nodo sin base de datos y forzarle a pedir governance y
//   subject desde 0;
//   rechazar la transferencia;
//   emitir un fact que vuelva a quedarle opaco;
//   hacer una segunda transferencia al mismo nodo;
//   reiniciarlo otra vez sin base de datos y volver a pedir todo.
//
// Comprobar:
//   la primera transferencia le abre en claro todo el histórico hasta ese
//   punto;
//   tras el reject, los facts nuevos vuelven a seguir su grant normal;
//   la última transferencia vuelve a mandar y abre en claro también los facts
//   que antes recibía opacos.
async fn test_viewpoints_transfer_restart_override_battery() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = nodes[0].api.clone();
    let witness_full = nodes[1].api.clone();
    let transfer_target = nodes[2].api.clone();
    let owner_public_key = owner.public_key();
    let owner_peer_id = owner.peer_id().to_string();
    let owner_listen_address = nodes[0].listen_address.clone();
    let witness_full_public_key = witness_full.public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![&witness_full, &transfer_target],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessFull",
                    "key": witness_full.public_key()
                },
                {
                    "name": "TransferTarget",
                    "key": transfer_target.public_key()
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
                        "WitnessFull",
                        "TransferTarget"
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
                                        "name": "WitnessFull",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "TransferTarget",
                                        "viewpoints": ["agua"]
                                    }
                                ]
                            },
                            {
                                "name": "TransferTarget",
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
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let _ = get_subject(&witness_full, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let _ = get_subject(&transfer_target, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact_viewpoints(
        &owner,
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
        &owner,
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

    let mixed_state =
        get_subject(&transfer_target, subject_id.clone(), Some(2), true)
            .await
            .unwrap();
    assert_eq!(
        mixed_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &mixed_state,
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    emit_transfer(
        &owner,
        subject_id.clone(),
        PublicKey::from_str(&transfer_target.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let pending_state =
        get_subject(&transfer_target, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(
        pending_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
        })
    );

    nodes[2].token.cancel();
    join_all(nodes[2].handler.iter_mut()).await;

    let target_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (target_node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", target_port),
        peers: vec![RoutingNode {
            peer_id: owner_peer_id.clone(),
            address: vec![owner_listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
    .await;
    let target = target_node.api.clone();
    node_running(&target).await.unwrap();

    target
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner_public_key).unwrap()),
        )
        .await
        .unwrap();
    target.update_subject(governance_id.clone()).await.unwrap();
    let _ = get_subject(&target, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    target
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_full_public_key).unwrap(),
            ),
        )
        .await
        .unwrap();
    target.update_subject(subject_id.clone()).await.unwrap();

    let restarted_pending_state =
        get_subject(&target, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(
        restarted_pending_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    let restarted_pending_events =
        get_events(&target, subject_id.clone(), 4, true)
            .await
            .unwrap();
    assert_tracker_fact_full(
        &restarted_pending_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &restarted_pending_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["basura"],
    );

    emit_reject(&target, subject_id.clone(), true)
        .await
        .unwrap();

    let rejected_state =
        get_subject(&target, subject_id.clone(), Some(4), true)
            .await
            .unwrap();
    assert_eq!(
        rejected_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );

    emit_fact_viewpoints(
        &owner,
        subject_id.clone(),
        json!({
            "ModTwo": {
                "data": 5
            }
        }),
        BTreeSet::from(["basura".to_owned()]),
        true,
    )
    .await
    .unwrap();

    let post_reject_state =
        get_subject(&target, subject_id.clone(), Some(5), true)
            .await
            .unwrap();
    assert_eq!(
        post_reject_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );
    let post_reject_events = get_events(&target, subject_id.clone(), 6, true)
        .await
        .unwrap();
    assert_tracker_fact_opaque(&post_reject_events[5].event, &["basura"])
        .unwrap();

    emit_transfer(
        &owner,
        subject_id.clone(),
        PublicKey::from_str(&target.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let pending_again_state =
        get_subject(&target, subject_id.clone(), Some(6), true)
            .await
            .unwrap();
    assert_eq!(
        pending_again_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 0
        })
    );

    target_node.token.cancel();
    let mut target_handlers = target_node.handler;
    join_all(target_handlers.iter_mut()).await;

    let target_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (target_node_2, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", target_port),
        peers: vec![RoutingNode {
            peer_id: owner_peer_id,
            address: vec![owner_listen_address],
        }],
        always_accept: true,
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
    .await;
    let target_2 = target_node_2.api.clone();
    node_running(&target_2).await.unwrap();

    target_2
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner_public_key).unwrap()),
        )
        .await
        .unwrap();
    target_2
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _ = get_subject(&target_2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    target_2
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_full_public_key).unwrap(),
            ),
        )
        .await
        .unwrap();
    target_2.update_subject(subject_id.clone()).await.unwrap();

    let restarted_pending_again_state =
        get_subject(&target_2, subject_id.clone(), Some(6), true)
            .await
            .unwrap();
    assert_eq!(
        restarted_pending_again_state.properties,
        json!({
            "one": 1,
            "two": 5,
            "three": 0
        })
    );
    let restarted_pending_again_events =
        get_events(&target_2, subject_id.clone(), 7, true)
            .await
            .unwrap();
    assert_tracker_fact_full(
        &restarted_pending_again_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &restarted_pending_again_events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &["basura"],
    );
    assert_tracker_fact_full(
        &restarted_pending_again_events[5].event,
        json!({
            "ModTwo": {
                "data": 5
            }
        }),
        &["basura"],
    );
}
