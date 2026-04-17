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
// B14: planificación multi-tramo con rangos discontinuos
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
