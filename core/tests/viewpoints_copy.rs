mod common;

use std::{collections::BTreeSet, str::FromStr};

use ave_common::{
    bridge::response::{
        RequestEventDB, TrackerEventVisibilityDB,
        TrackerEventVisibilityRangeDB, TrackerStoredVisibilityDB,
        TrackerStoredVisibilityRangeDB, TrackerVisibilityModeDB,
    },
    identity::PublicKey,
};
use ave_core::auth::AuthWitness;
use common::{
    assert_tracker_fact_full, assert_tracker_visibility,
    create_and_authorize_governance, create_nodes_and_connections,
    create_subject, emit_confirm, emit_eol, emit_fact, emit_fact_viewpoints,
    emit_reject, emit_transfer, get_events, get_subject,
};
use serde_json::json;
use test_log::test;

use crate::common::{
    CreateNodesAndConnectionsConfig, assert_tracker_fact_opaque,
};

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

#[test(tokio::test)]
// B09: proyección `TrackerFactFull -> TrackerFactOpaque`
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
// B11: copia manual, auth y auto-update
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
