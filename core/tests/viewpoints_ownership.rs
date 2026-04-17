mod common;

use std::{collections::BTreeSet, str::FromStr, sync::atomic::Ordering};

use ave_common::{
    bridge::response::{
        TrackerEventVisibilityDB, TrackerEventVisibilityRangeDB,
        TrackerStoredVisibilityDB, TrackerStoredVisibilityRangeDB,
        TrackerVisibilityModeDB,
    },
    identity::PublicKey,
};
use ave_core::auth::AuthWitness;
use ave_network::{NodeType, RoutingNode};
use common::{
    CreateNodeConfig, assert_tracker_fact_full, assert_tracker_visibility,
    create_and_authorize_governance, create_node, create_nodes_and_connections,
    create_subject, emit_confirm, emit_fact, emit_fact_viewpoints, emit_reject,
    emit_transfer, get_events, get_subject, node_running,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    CreateNodesAndConnectionsConfig, PORT_COUNTER, assert_tracker_fact_opaque,
};

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

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
