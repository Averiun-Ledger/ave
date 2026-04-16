mod common;

use std::collections::BTreeSet;

use ave_common::bridge::response::{
    TrackerEventVisibilityDB, TrackerEventVisibilityRangeDB,
    TrackerStoredVisibilityDB, TrackerStoredVisibilityRangeDB,
    TrackerVisibilityModeDB,
};
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
// B13: mezclas extremas
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
