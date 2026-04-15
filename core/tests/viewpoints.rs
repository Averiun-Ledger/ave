mod common;

use std::{collections::BTreeSet, str::FromStr};

use ave_common::{
    bridge::{
        request::EventsQuery,
        response::{
            LedgerDB, RequestEventDB, SubjectDB, TrackerEventVisibilityDB,
            TrackerEventVisibilityRangeDB, TrackerStoredVisibilityDB,
            TrackerStoredVisibilityRangeDB, TrackerVisibilityModeDB,
        },
    },
    identity::{DigestIdentifier, PublicKey},
};
use ave_core::{Api, auth::AuthWitness};
use common::{
    assert_tracker_fact_full, create_and_authorize_governance,
    create_nodes_and_connections, create_subject, emit_fact,
    emit_fact_viewpoints, get_subject,
};
use serde_json::json;
use test_log::test;

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

fn assert_tracker_fact_opaque(
    event: &RequestEventDB,
    expected_viewpoints: &[&str],
) {
    match event {
        RequestEventDB::TrackerFactOpaque { viewpoints, .. } => {
            assert_eq!(
                viewpoints,
                &expected_viewpoints
                    .iter()
                    .map(|viewpoint| viewpoint.to_string())
                    .collect::<Vec<_>>()
            );
        }
        event => panic!("unexpected opaque fact event: {event:?}"),
    }
}

async fn get_all_events(
    node: &Api,
    subject_id: DigestIdentifier,
) -> Vec<LedgerDB> {
    node.get_events(
        subject_id,
        EventsQuery {
            quantity: Some(1000),
            page: Some(0),
            reverse: Some(false),
            event_request_ts: None,
            event_ledger_ts: None,
            sink_ts: None,
            event_type: None,
        },
    )
    .await
    .unwrap()
    .events
}

fn assert_tracker_visibility(
    state: &SubjectDB,
    expected_mode: TrackerVisibilityModeDB,
    expected_stored: Vec<TrackerStoredVisibilityRangeDB>,
    expected_events: Vec<TrackerEventVisibilityRangeDB>,
) {
    let visibility = state
        .tracker_visibility
        .as_ref()
        .expect("tracker subjects must expose tracker_visibility");

    assert_eq!(visibility.mode, expected_mode);
    assert_eq!(visibility.stored_ranges, expected_stored);
    assert_eq!(visibility.event_ranges, expected_events);
}

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
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0]],
        vec![],
        true,
        false,
    )
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
    );
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
    );

    let owner_events = owner
        .get_events(
            subject_id.clone(),
            EventsQuery {
                quantity: Some(10),
                page: Some(0),
                reverse: Some(false),
                event_request_ts: None,
                event_ledger_ts: None,
                sink_ts: None,
                event_type: None,
            },
        )
        .await
        .unwrap();
    let witness_events = witness
        .get_events(
            subject_id.clone(),
            EventsQuery {
                quantity: Some(10),
                page: Some(0),
                reverse: Some(false),
                event_request_ts: None,
                event_ledger_ts: None,
                sink_ts: None,
                event_type: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(owner_events.events.len(), 2);
    assert_eq!(witness_events.events.len(), 2);

    assert_tracker_fact_full(
        &owner_events.events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_full(
        &witness_events.events[1].event,
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
    );
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
    );

    let owner_events = owner
        .get_events(
            subject_id.clone(),
            EventsQuery {
                quantity: Some(10),
                page: Some(0),
                reverse: Some(false),
                event_request_ts: None,
                event_ledger_ts: None,
                sink_ts: None,
                event_type: None,
            },
        )
        .await
        .unwrap();
    let witness_events = witness
        .get_events(
            subject_id.clone(),
            EventsQuery {
                quantity: Some(10),
                page: Some(0),
                reverse: Some(false),
                event_request_ts: None,
                event_ledger_ts: None,
                sink_ts: None,
                event_type: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(owner_events.events.len(), 3);
    assert_eq!(witness_events.events.len(), 3);

    assert_tracker_fact_full(
        &owner_events.events[2].event,
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        &[],
    );
    assert_tracker_fact_full(
        &witness_events.events[2].event,
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
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0], vec![0], vec![0]],
        vec![],
        true,
        false,
    )
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

    let _state = get_subject(witness_mixed, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let _state = get_subject(witness_agua, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let _state = get_subject(witness_hash, governance_id.clone(), Some(1), true)
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
    let agua_state = get_subject(witness_agua, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let hash_state = get_subject(witness_hash, subject_id.clone(), Some(3), true)
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
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec![],
                },
            },
        ],
    );
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
    );

    let mixed_events = get_all_events(witness_mixed, subject_id.clone()).await;
    let agua_events = get_all_events(witness_agua, subject_id.clone()).await;
    let hash_events = get_all_events(witness_hash, subject_id.clone()).await;
    let vidrio_events = get_all_events(witness_vidrio, subject_id.clone()).await;

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
    assert_tracker_fact_opaque(&agua_events[2].event, &["basura"]);
    assert_tracker_fact_full(
        &agua_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );

    assert_tracker_fact_opaque(&hash_events[1].event, &["agua"]);
    assert_tracker_fact_opaque(&hash_events[2].event, &["basura"]);
    assert_tracker_fact_full(
        &hash_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &[],
    );

    assert_tracker_fact_opaque(&vidrio_events[1].event, &["agua"]);
    assert_tracker_fact_opaque(&vidrio_events[2].event, &["basura"]);
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
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0]],
        vec![],
        true,
        false,
    )
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
    );
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
    );

    let owner_events = get_all_events(owner, subject_id.clone()).await;
    let witness_events = get_all_events(witness, subject_id.clone()).await;

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
    assert_tracker_fact_opaque(&witness_events[2].event, &["agua"]);
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
#[ignore = "test plan placeholder"]
// B04: ventana de búsqueda por batch
//
// Setup:
//   usar el mismo subject con `actual_sn = None`, `5` y `100`;
//   fijar `ledger_batch_size = 100`.
//
// Acción:
//   lanzar update.
//
// Comprobar:
//   la ventana es `0..49`, `6..105` o `101..200` según el caso;
//   governance no usa esta ventana, trackers sí.
//   si `actual_sn` ya está por encima del límite accesible, no hay ventana útil.
async fn test_viewpoints_batch_window_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
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
async fn test_viewpoints_requester_perspective_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
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
async fn test_viewpoints_transfer_override_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
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
async fn test_viewpoints_reject_and_old_owner_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B08: selección del mejor witness para actualizar
//
// Setup:
//   preparar 2 o 3 witnesses con distintos techos:
//   uno mejor en `Clear`, otro mejor en `Hash`, otro con más `sn`.
//
// Acción:
//   lanzar update y forzar algún timeout.
//
// Comprobar:
//   primero se elige el mejor `Clear`;
//   luego el mejor siguiente tramo;
//   si falla uno, se replanifica desde el `sn` alcanzado.
//   si un witness ofrece `clear_sn` corto y más histórico opaco detrás, el primer
//   request corta en `clear_sn` y no intenta mezclarlo todo de golpe.
async fn test_viewpoints_update_selection_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
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
async fn test_viewpoints_projection_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B10: distribución inmediata del último evento
//
// Setup:
//   crear distintos últimos eventos:
//   fact público, fact segmentado, fact opaco y transfer.
//   añadir también un fact con viewpoints que el witness no tiene.
//
// Acción:
//   distribuir el último evento a varios witnesses.
//
// Comprobar:
//   cada witness recibe el mismo `sn`;
//   la proyección cambia según su acceso;
//   si hay gap de `sn`, cae al update normal.
//   un witness sin viewpoint válido recibe el fact opaco.
//   un `NonFact` siempre llega en claro aunque el witness sea parcial.
async fn test_viewpoints_last_event_distribution_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
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
async fn test_viewpoints_copy_paths_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B12: tracker mínimo y persistencia del estado auxiliar
//
// Setup:
//   crear un tracker full;
//   después bajarlo a opaque;
//   reiniciar el nodo.
//   incluir facts públicos, facts con viewpoints y `NonFact`.
//
// Acción:
//   pedir histórico y probar aplicación de patch antes y después del reinicio.
//
// Comprobar:
//   el tracker solo usa `visibility_mode`;
//   los rangos siguen vivos fuera;
//   el reinicio no cambia la respuesta histórica.
//   un tracker que quedó en `Opaque` no vuelve a `Full` por error tras reinicio.
//   si faltan spans de visibilidad almacenada o de evento, la respuesta cae a opaco.
async fn test_viewpoints_tracker_minimal_state_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
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
async fn test_viewpoints_extreme_combinations_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
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
async fn test_viewpoints_update_disjoint_ranges_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B15: reinicio de ronda por objetivo real
//
// Setup:
//   preparar casos con objetivo alcanzado, no alcanzado y progreso parcial.
//
// Acción:
//   dejar vencer el timeout de la ronda.
//
// Comprobar:
//   si el objetivo ya se alcanzó, no reintenta;
//   si hubo progreso parcial, reinicia desde ahí;
//   no aparecen dos rondas activas a la vez.
async fn test_viewpoints_update_retry_target_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B16: descubrimiento de tipo con `our_sn = None`
//
// Setup:
//   usar un subject desconocido;
//   preparar ofertas remotas de governance y de tracker.
//
// Acción:
//   lanzar update sin `our_sn`.
//
// Comprobar:
//   si el subject es governance, sigue `highest sn`;
//   si es tracker, sigue planner por rangos;
//   un caso de un solo witness no deja update residual.
//   si un witness no tiene acceso útil, su oferta se ignora.
async fn test_viewpoints_update_subject_kind_discovery_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B17: subject desconocido y ownership resuelto en el mismo batch
//
// Setup:
//   usar un receptor que no conoce el subject;
//   preparar un batch con `Create`, facts y transferencias.
//
// Acción:
//   enviar el batch completo de una vez.
//
// Comprobar:
//   el acceso final no se decide solo por el `Create`;
//   manda el ownership efectivo al final del batch;
//   un sender no creator puede seguir siendo válido si el batch lo justifica.
//   si el batch empieza en `sn=0`, el cálculo usa `data.gov_version` como fallback.
async fn test_viewpoints_unknown_subject_ownership_in_batch_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B18: autorización y continuidad cuando cambia owner o witness
//
// Setup:
//   partir un histórico en dos o tres batches;
//   hacer que entre medias cambie owner, witness o governance version.
//
// Acción:
//   enviar los batches seguidos.
//
// Comprobar:
//   un batch no se autoriza solo por el primer evento;
//   el siguiente batch puede requerir otro sender;
//   un sender válido para un tramo puede dejar de serlo para el siguiente.
//   si cambia la `gov_version` en mitad del histórico, la decisión usa la versión de cada tramo.
async fn test_viewpoints_batch_auth_transition_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B19: validación de inputs de viewpoints y grants
//
// Setup:
//   preparar facts y creator witnesses con:
//   `AllViewpoints`;
//   `AllViewpoints + agua`;
//   viewpoints desconocidos;
//   viewpoints vacíos;
//   nombres repetidos o con formato raro.
//
// Acción:
//   intentar crear governance/facts/evaluations con esos datos.
//
// Comprobar:
//   `AllViewpoints` solo vale solo;
//   un viewpoint desconocido se rechaza;
//   governance fact no acepta viewpoints si no debe;
//   un input mal formado falla limpio y no deja estado parcial.
async fn test_viewpoints_input_validation_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B20: visibilidad almacenada vs visibilidad del evento
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
// B21: namespace y schema combinados con viewpoints
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
// B22: cambio de creator con mismo schema y mismo witness
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
// B23: `clear_sn`, prefijo contiguo y corte del primer batch
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
// B24: bordes de `sn`, `gov_version` y límites sin oferta útil
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
