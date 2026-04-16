mod common;

use std::{collections::BTreeSet, str::FromStr};

use ave_common::{
    bridge::response::{
        TrackerEventVisibilityDB, TrackerEventVisibilityRangeDB,
        TrackerStoredVisibilityDB, TrackerStoredVisibilityRangeDB,
        TrackerVisibilityModeDB,
    },
    identity::PublicKey,
};
use ave_core::auth::AuthWitness;
use common::{
    assert_tracker_fact_full, assert_tracker_visibility,
    create_and_authorize_governance, create_nodes_and_connections,
    create_subject, emit_fact, emit_fact_viewpoints, get_events, get_subject,
};
use serde_json::json;
use test_log::test;

use crate::common::{
    CreateNodesAndConnectionsConfig, assert_tracker_fact_opaque,
};

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
