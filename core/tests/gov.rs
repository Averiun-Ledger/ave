use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::atomic::Ordering,
    time::Duration,
};

mod common;

use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    bridge::{
        request::ApprovalStateRes,
        response::{EvalResDB, RequestEventDB},
    },
    identity::{
        DigestIdentifier, PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
    response::RequestState,
    sink::DataToSinkEvent,
};
use ave_core::Api;
use ave_core::auth::AuthWitness;
use ave_core::governance::data::GovernanceData;
use ave_core::governance::model::{
    CreatorWitness, PolicyGov, PolicySchema, Quorum, RoleCreator,
    RoleGovIssuer, RolesGov, RolesSchema, RolesTrackerSchemas, Schema,
};
use ave_core::governance::witnesses_register::{
    TrackerDeliveryMode, TrackerDeliveryRange,
};
use ave_core::helpers::network::test_faults::{
    FaultAction, FaultDirection, FaultMessage, FaultRule,
};
use ave_core::helpers::network::{ActorMessage, NetworkMessage};
use ave_core::model::event::Ledger;
use ave_core::update::{UpdateSubjectKind, UpdateWitnessOffer};

use ave_network::{ComunicateInfo, NodeType, RoutingNode};
use common::{
    CHANGED_SCHEMA_CONTRACT, CreateNodeConfig, CreateNodesAndConnectionsConfig,
    EXAMPLE_CONTRACT, EXAMPLE_CONTRACT_V2, INVALID_EXAMPLE_CONTRACT,
    assert_governance_properties_eq, create_and_authorize_governance,
    create_nodes_and_connections, create_subject, emit_approve, emit_confirm,
    emit_eol, emit_fact, emit_fact_viewpoints, emit_reject, emit_transfer,
    get_events, get_subject, governance_properties, wait_sink_events,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    PORT_COUNTER, create_node, fast_update_sync, get_abort_request,
    node_running, wait_request, wait_request_state,
};

#[test(tokio::test)]
//  Verificar que update protocol actualiza pasivamente la gobernanza, a un testigo.
async fn test_update_protocol() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();
    let node2 = nodes[1].api.clone();
    let node3 = nodes[2].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&node2]).await;

    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "AveNode3"
                    ]
                }
            },
        },
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.public_key()
                }
            ]
        }
    });

    let _request_id = emit_fact(&node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    node2
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node1.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node3
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node1.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node3.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "Fake",
                "key": fake_node
            }
        ]
    }});

    emit_fact(&node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: node3.peer_id().to_string(),
        address: vec![nodes[2].listen_address.clone()],
    }];

    let (node_new_node2, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address,
        peers,
        always_accept: true,
        is_service: true,
        keys: Some(nodes[1].keys.clone()),
        local_db: Some(_dirs[2].path().to_path_buf()),
        ext_db: Some(_dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let new_node2 = node_new_node2.api.clone();
    node_running(&new_node2).await.unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(2), false)
        .await
        .unwrap();
}
#[test(tokio::test)]
//  El owner perdió el ledger, se lo pidió a un testigo que no tenía la última versión
// la siguiente request se aborta.
async fn test_approve_invalid_gov_version() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();
    let node2 = nodes[1].api.clone();
    let node3 = nodes[2].api.clone();

    let governance_id =
        create_and_authorize_governance(&node2, vec![&node1, &node3]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": node1.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.public_key()
                }
            ]
        },
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "approver": ["AveNode3"]
                }
            }
        }
    });

    let request_id = emit_fact(&node2, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    node1
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node2.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node1.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node3
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node2.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node3.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode4",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&node2, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        &node3,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    let _state = get_subject(&node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node3.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: node1.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_node2, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
    .await;
    let new_node2 = node_new_node2.api.clone();
    node_running(&new_node2).await.unwrap();

    assert!(
        new_node2
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_node2
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node1.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_node2
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode5",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&new_node2, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        &new_node2,
        request_id.clone(),
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    let aborts =
        get_abort_request(&new_node2, governance_id.clone(), request_id)
            .await
            .unwrap();

    assert_eq!(aborts.events.len(), 1);
    assert_eq!(
        aborts.events[0].error,
        "Abort approval, governance update is required by signer: local=2, request=1"
    );

    new_node2
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(node3.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_node2
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode5",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&new_node2, governance_id.clone(), json, false)
        .await
        .unwrap();

    emit_approve(
        &new_node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        &node3,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
}
#[test(tokio::test)]
// El el init state es invalido, se aborata la request
async fn test_invalid_init_state() {
    //  Ephemeral -> Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let node = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                    }
                }
            ]
        },
    });

    emit_fact(node, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node, governance_id.clone(), None, true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, node.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_governance_properties_eq(
        state.properties,
        GovernanceData {
            version: 0,
            members: BTreeMap::from([(
                "Owner".to_owned(),
                PublicKey::from_str(node.public_key()).unwrap(),
            )]),
            roles_gov: RolesGov {
                approver: BTreeSet::from(["Owner".to_owned()]),
                evaluator: BTreeSet::from(["Owner".to_owned()]),
                validator: BTreeSet::from(["Owner".to_owned()]),
                witness: BTreeSet::from(["Owner".to_owned()]),
                issuer: RoleGovIssuer {
                    signers: BTreeSet::from(["Owner".to_owned()]),
                    any: false,
                },
                compiler: BTreeSet::from(["Owner".to_owned()]),
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
                compile: Quorum::Majority,
            },
            schemas: BTreeMap::new(),
            roles_schema: BTreeMap::new(),
            roles_tracker_schemas: RolesTrackerSchemas::default(),
            toolchain: GovernanceData::default().toolchain,
            policies_schema: BTreeMap::new(),
        },
    );
}
#[test(tokio::test)]
//  Verificar que se puede crear una gobernanza, sujeto y emitir un evento además de recibir la copia
async fn test_governance_and_subject_copy_with_approve() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
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
                        "AveNode2"
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
                                    "name": "AveNode2",
                                    "namespace": [],
                                    "quantity": 2
                                }
                            ],
                            "issuer": [
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

    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let (subject_id, ..) =
        create_subject(node2, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node2, subject_id.clone(), json, true)
        .await
        .unwrap();

    for i in 0..9 {
        let json = json!({
            "ModTwo": {
                "data": i + 1,
            }
        });

        emit_fact(node2, subject_id.clone(), json, false)
            .await
            .unwrap();
    }

    let json = json!({
        "ModTwo": {
            "data": 9 + 1,
        }
    });

    emit_fact(node2, subject_id.clone(), json, true)
        .await
        .unwrap();

    let events = node2
        .get_first_or_end_events(
            subject_id.clone(),
            Some(11),
            Some(false),
            None,
        )
        .await
        .unwrap();

    assert_eq!(events.len(), 11);

    let state = get_subject(node1, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node2.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node2.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 11);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 10
        })
    );

    let state = get_subject(node2, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node2.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node2.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 11);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 10
        })
    );
}
#[test(tokio::test)]
// Caso de uso básico 1 bootstrap (intermediario), 1 ephemeral(issuer de subject),
// 1 addressable(owner de la gobernanza)
async fn test_basic_use_case_1b_1e_1a() {
    //  Ephemeral -> Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            ephemeral: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let bootstrap = &nodes[0].api;
    let addressable = &nodes[1].api;
    let ephimeral = &nodes[2].api;

    let governance_id = create_and_authorize_governance(
        addressable,
        vec![bootstrap, ephimeral],
    )
    .await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": bootstrap.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": ephimeral.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"],
                }
            }
        }
    });

    emit_fact(addressable, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(addressable, governance_id.clone(), None, true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    let expected = GovernanceData {
        version: 1,
        members: BTreeMap::from([
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(bootstrap.public_key()).unwrap(),
            ),
            (
                "AveNode3".to_owned(),
                PublicKey::from_str(ephimeral.public_key()).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(addressable.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode2".to_owned(),
                "AveNode3".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected.clone());

    let state = get_subject(bootstrap, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_governance_properties_eq(state.properties, expected.clone());

    ephimeral
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let state = get_subject(ephimeral, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
async fn test_many_schema_in_one_governance() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example1",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Example2",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Example3",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
    });
    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), None, true)
            .await
            .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    let expected = GovernanceData {
        version: 1,
        members: BTreeMap::from([(
            "Owner".to_owned(),
            PublicKey::from_str(owner_governance.public_key()).unwrap(),
        )]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::from([
            (
                SchemaType::Type("Example1".to_owned()),
                Schema {
                    contract: EXAMPLE_CONTRACT.to_owned(),
                    initial_value: ValueWrapper(
                        json!({"one": 0, "two": 0, "three": 0}),
                    ),
                    viewpoints: BTreeSet::new(),
                },
            ),
            (
                SchemaType::Type("Example2".to_owned()),
                Schema {
                    contract: EXAMPLE_CONTRACT.to_owned(),
                    initial_value: ValueWrapper(
                        json!({"one": 0, "two": 0, "three": 0}),
                    ),
                    viewpoints: BTreeSet::new(),
                },
            ),
            (
                SchemaType::Type("Example3".to_owned()),
                Schema {
                    contract: EXAMPLE_CONTRACT.to_owned(),
                    initial_value: ValueWrapper(
                        json!({"one": 0, "two": 0, "three": 0}),
                    ),
                    viewpoints: BTreeSet::new(),
                },
            ),
        ]),
        roles_schema: BTreeMap::from([
            (
                SchemaType::Type("Example1".to_owned()),
                RolesSchema::default(),
            ),
            (
                SchemaType::Type("Example2".to_owned()),
                RolesSchema::default(),
            ),
            (
                SchemaType::Type("Example3".to_owned()),
                RolesSchema::default(),
            ),
        ]),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::from([
            (
                SchemaType::Type("Example1".to_owned()),
                PolicySchema {
                    evaluate: Quorum::Majority,
                    validate: Quorum::Majority,
                },
            ),
            (
                SchemaType::Type("Example2".to_owned()),
                PolicySchema {
                    evaluate: Quorum::Majority,
                    validate: Quorum::Majority,
                },
            ),
            (
                SchemaType::Type("Example3".to_owned()),
                PolicySchema {
                    evaluate: Quorum::Majority,
                    validate: Quorum::Majority,
                },
            ),
        ]),
    };
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
// Testear la transferencia de gobernanza
async fn test_transfer_event_governance_1() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let future_owner = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![future_owner])
            .await;
    // add member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": future_owner.public_key()
                }
            ]
        },
            "roles": {
                "governance": {
                    "add": {
                        "witness": ["AveNode1"],
                        "compiler": ["AveNode1"],
                    }
                }
            }
    });
    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        owner_governance,
        governance_id.clone(),
        PublicKey::from_str(future_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    // Confirm transfer event
    emit_confirm(future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode2",
                "key": fake_node
            }
        ]
    }});

    emit_fact(future_owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    let expected = GovernanceData {
        version: 4,
        members: BTreeMap::from([
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(future_owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected);

    let state =
        get_subject(owner_governance, governance_id.clone(), None, true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, Some(future_owner.public_key().to_string()));
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(future_owner.public_key()).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected);
}
/// Bounded poll for a governance owner change: an unreachable confirm
/// must fail the test instead of hanging it forever.
async fn wait_gov_owner(
    node: &Api,
    governance_id: DigestIdentifier,
    expected_owner: String,
    max_secs: u64,
) {
    for _ in 0..(max_secs * 10 / 3) {
        if let Ok(state) = node.get_subject_state(governance_id.clone()).await
            && state.owner == expected_owner
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!(
        "timeout waiting for governance {governance_id} owner {expected_owner}"
    );
}
#[test(tokio::test)]
// Transferencia donde un tercer nodo es el único validador continuo:
// tras el transfer el tercer nodo sigue validando pero la clave del
// owner cambió, así que su worker tiene que aprender la nueva clave
// para aceptar el confirm. El confirm solo commitea si el tercer nodo
// lo valida (quórum 2 de 2 junto al nuevo owner).
async fn test_transfer_confirm_with_third_party_validator() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let old_owner = &nodes[0].api;
    let new_owner = &nodes[1].api;
    let third = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(old_owner, vec![new_owner, third])
            .await;
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "NewOwner",
                    "key": new_owner.public_key()
                },
                {
                    "name": "Third",
                    "key": third.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["NewOwner", "Third"],
                    "validator": ["Third"]
                }
            }
        }
    });
    emit_fact(old_owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The third node validates the transfer together with the old
    // owner: its worker still expects the old owner key here.
    emit_transfer(
        old_owner,
        governance_id.clone(),
        PublicKey::from_str(new_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    // The confirm is signed by the new owner: without the key update
    // the third node drops it and the ownership never changes.
    emit_confirm(new_owner, governance_id.clone(), None, false)
        .await
        .unwrap();
    wait_gov_owner(
        new_owner,
        governance_id.clone(),
        new_owner.public_key().to_string(),
        60,
    )
    .await;

    let state = get_subject(new_owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.owner, new_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert!(state.active);
}
#[test(tokio::test)]
// Testear la transferencia de gobernanza, pero el owner se queda como miembro
async fn test_transfer_event_governance_2() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let future_owner = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![future_owner])
            .await;

    // Auth governance in old owner, in future he will be a normal member and need auth governance for receive a ledger copy.
    owner_governance
        .authorize_governance(governance_id.clone(), AuthWitness::None)
        .await
        .unwrap();
    // add member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": future_owner.public_key()
                }
            ]
        },
            "roles": {
                "governance": {
                    "add": {
                        "witness": ["AveNode1"],
                        "compiler": ["AveNode1"],
                    }
                }
            }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        owner_governance,
        governance_id.clone(),
        PublicKey::from_str(future_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let transfer_data = owner_governance
        .get_pending_transfers(1000, 0)
        .await
        .unwrap();
    assert_eq!(
        transfer_data[0].actual_owner.to_string(),
        owner_governance.public_key()
    );
    assert_eq!(
        transfer_data[0].new_owner.to_string(),
        future_owner.public_key()
    );
    assert_eq!(transfer_data[0].subject_id, governance_id);

    let transfer_data =
        future_owner.get_pending_transfers(1000, 0).await.unwrap();
    assert_eq!(
        transfer_data[0].actual_owner.to_string(),
        owner_governance.public_key()
    );
    assert_eq!(
        transfer_data[0].new_owner.to_string(),
        future_owner.public_key()
    );
    assert_eq!(transfer_data[0].subject_id, governance_id);

    // Confirm transfer event
    emit_confirm(
        future_owner,
        governance_id.clone(),
        Some("AveNode_Old".to_owned()),
        true,
    )
    .await
    .unwrap();

    let transfer_data = owner_governance
        .get_pending_transfers(1000, 0)
        .await
        .unwrap();
    assert!(transfer_data.is_empty());

    let transfer_data =
        future_owner.get_pending_transfers(1000, 0).await.unwrap();
    assert!(transfer_data.is_empty());

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    // add new fake member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": fake_node
                }
            ]
        }
    });

    emit_fact(future_owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    let expected = GovernanceData {
        version: 4,
        members: BTreeMap::from([
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node).unwrap(),
            ),
            (
                "AveNode_Old".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(future_owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode_Old".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected.clone());

    let state =
        get_subject(owner_governance, governance_id.clone(), None, true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
async fn test_governance_fail_approve() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode1"],
                }
            }
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_governance_properties_eq(
        state.properties,
        GovernanceData {
            version: 0,
            members: BTreeMap::from([(
                "Owner".to_owned(),
                PublicKey::from_str(node1.public_key()).unwrap(),
            )]),
            roles_gov: RolesGov {
                approver: BTreeSet::from(["Owner".to_owned()]),
                evaluator: BTreeSet::from(["Owner".to_owned()]),
                validator: BTreeSet::from(["Owner".to_owned()]),
                witness: BTreeSet::from(["Owner".to_owned()]),
                issuer: RoleGovIssuer {
                    signers: BTreeSet::from(["Owner".to_owned()]),
                    any: false,
                },
                compiler: BTreeSet::from(["Owner".to_owned()]),
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
                compile: Quorum::Majority,
            },
            schemas: BTreeMap::new(),
            roles_schema: BTreeMap::new(),
            roles_tracker_schemas: RolesTrackerSchemas::default(),
            toolchain: GovernanceData::default().toolchain,
            policies_schema: BTreeMap::new(),
        },
    );
}
#[test(tokio::test)]
// A rejected governance fact commits to the ledger but must not touch
// properties or registers: what failed only leaves its ledger record.
// A later approved fact proves the apply path still advances.
async fn test_failed_fact_writes_no_registers() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let owner_key = PublicKey::from_str(node1.public_key()).unwrap();
    let evaluators = node1
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(evaluators, vec![owner_key.clone()]);

    let fake_key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_key.clone()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": ["AveNode1"],
                }
            }
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    // Ledger record exists, properties untouched.
    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.owner, node1.public_key());
    assert_governance_properties_eq(
        state.properties,
        GovernanceData {
            version: 0,
            members: BTreeMap::from([("Owner".to_owned(), owner_key.clone())]),
            roles_gov: RolesGov {
                approver: BTreeSet::from(["Owner".to_owned()]),
                evaluator: BTreeSet::from(["Owner".to_owned()]),
                validator: BTreeSet::from(["Owner".to_owned()]),
                witness: BTreeSet::from(["Owner".to_owned()]),
                issuer: RoleGovIssuer {
                    signers: BTreeSet::from(["Owner".to_owned()]),
                    any: false,
                },
                compiler: BTreeSet::from(["Owner".to_owned()]),
            },
            policies_gov: PolicyGov {
                approve: Quorum::Majority,
                evaluate: Quorum::Majority,
                validate: Quorum::Majority,
                compile: Quorum::Majority,
            },
            schemas: BTreeMap::new(),
            roles_schema: BTreeMap::new(),
            roles_tracker_schemas: RolesTrackerSchemas::default(),
            toolchain: GovernanceData::default().toolchain,
            policies_schema: BTreeMap::new(),
        },
    );

    // Registers untouched: the rejected grant never landed.
    let evaluators = node1
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(evaluators, vec![owner_key.clone()]);

    // An approved follow-up still applies and advances markers.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_key
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": ["AveNode1"],
                }
            }
        }
    });

    let request_id_followup =
        emit_fact(node1, governance_id.clone(), json, true)
            .await
            .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id_followup,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert_eq!(governance_properties(state.properties).version, 1);

    let evaluators = node1
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert!(evaluators.contains(&owner_key));
    assert!(evaluators.contains(&PublicKey::from_str(&fake_key).unwrap()));

    node_running(node1).await.unwrap();
}
#[test(tokio::test)]
// Varios approvers y todos dicen que sí, se cumple el quorum.
async fn test_governance_manual_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Approver1".to_owned(),
                PublicKey::from_str(approver_1.public_key()).unwrap(),
            ),
            (
                "Approver2".to_owned(),
                PublicKey::from_str(approver_2.public_key()).unwrap(),
            ),
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(&fake_node).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
// Varios approvers y todos dicen que sí, se cumple el quorum. de forma automática.
async fn test_governance_auto_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Approver1".to_owned(),
                PublicKey::from_str(approver_1.public_key()).unwrap(),
            ),
            (
                "Approver2".to_owned(),
                PublicKey::from_str(approver_2.public_key()).unwrap(),
            ),
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(&fake_node).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
// Varios approvers pero uno dice que no y el quorum no se cumple.
async fn test_governance_not_quorum_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "approver": ["Approver1", "Approver2"],
                    "witness": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let expected = GovernanceData {
        version: 1,
        members: BTreeMap::from([
            (
                "Approver1".to_owned(),
                PublicKey::from_str(approver_1.public_key()).unwrap(),
            ),
            (
                "Approver2".to_owned(),
                PublicKey::from_str(approver_2.public_key()).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "Approver1".to_owned(),
                "Approver2".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Fixed(100),
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(approver_2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
// Se añade un evaluador, se evalua, se le elimina y se vuelve a evaluar.
async fn test_change_roles_gov() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let eval_node = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![eval_node])
            .await;
    // add member to governance
    let json: serde_json::Value = json!({
    "roles": {
        "governance": {
            "add": {
                "witness": ["AveNode1"],
                "evaluator": ["AveNode1"],
                "validator": ["AveNode1"],
                "compiler": ["AveNode1"]
            }
        }
    },
    "members": {
        "add": [
            {
                "name": "AveNode1",
                "key": eval_node.public_key()
            }
        ]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let fake_node_1 = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode2",
                "key": fake_node_1
            }
        ]
    },
    "roles": {
        "governance": {
            "add": {
                "compiler": ["AveNode2"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(eval_node.public_key()).unwrap(),
            ),
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node_1).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            validator: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            witness: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from([
                "AveNode1".to_owned(),
                "AveNode2".to_owned(),
                "Owner".to_owned(),
            ]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(eval_node, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);

    let json = json!({
    "roles": {
        "governance": {
            "remove": {
                "evaluator": ["AveNode1"],
                "validator": ["AveNode1"],
                "compiler": ["AveNode1"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 3,
        members: BTreeMap::from([
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(eval_node.public_key()).unwrap(),
            ),
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node_1).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from([
                "AveNode2".to_owned(),
                "Owner".to_owned(),
            ]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 3);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(eval_node, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 3);
    assert_governance_properties_eq(state.properties, expected);

    let fake_node_2 = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode3",
                    "key": fake_node_2
                }
            ]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 4,
        members: BTreeMap::from([
            (
                "AveNode1".to_owned(),
                PublicKey::from_str(eval_node.public_key()).unwrap(),
            ),
            (
                "AveNode2".to_owned(),
                PublicKey::from_str(&fake_node_1).unwrap(),
            ),
            (
                "AveNode3".to_owned(),
                PublicKey::from_str(&fake_node_2).unwrap(),
            ),
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from([
                "AveNode1".to_owned(),
                "Owner".to_owned(),
            ]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from([
                "AveNode2".to_owned(),
                "Owner".to_owned(),
            ]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(4), true)
            .await
            .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    assert_governance_properties_eq(state.properties, expected.clone());
    let state = get_subject(eval_node, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 4);
    assert_governance_properties_eq(state.properties, expected);

    // SN 5 (fallido): quitar el rol compiler al Owner está protegido por
    // check_basic_gov, como el resto de roles básicos.
    let json = json!({
    "roles": {
        "governance": {
            "remove": {
                "compiler": ["Owner"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // SN 6 (fallido): dar el rol compiler a un miembro que no existe.
    let json = json!({
    "roles": {
        "governance": {
            "add": {
                "compiler": ["NotAMember"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // SN 7 (fallido): dar el rol compiler a AveNode2, que ya lo tiene.
    let json = json!({
    "roles": {
        "governance": {
            "add": {
                "compiler": ["AveNode2"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // SN 8 (fallido): quitar el rol compiler a AveNode1, que ya no lo
    // tiene (se le quitó en el SN 3).
    let json = json!({
    "roles": {
        "governance": {
            "remove": {
                "compiler": ["AveNode1"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Los cuatro eventos commitean como fallidos: el sn avanza pero las
    // propiedades no cambian (compiler sigue siendo {AveNode2, Owner}).
    let state =
        get_subject(owner_governance, governance_id.clone(), Some(8), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 4);
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["AveNode2".to_owned(), "Owner".to_owned()])
    );

    // SN 9: se elimina al MIEMBRO AveNode2 (sin evento de roles). La
    // cascada de borrado (remove_member_role) debe quitarlo también del
    // rol compiler.
    let json = json!({
    "members": {
        "remove": ["AveNode2"]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(9), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 5);
    assert!(!properties.members.contains_key("AveNode2"));
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["Owner".to_owned()])
    );

    // SN 10: se devuelve el rol compiler a AveNode1 (nodo real). A partir
    // de aquí el quórum de compile Majority exige el 2/2: Owner compila
    // en local y AveNode1 por red.
    let json = json!({
    "roles": {
        "governance": {
            "add": {
                "compiler": ["AveNode1"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(10), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 6);
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["AveNode1".to_owned(), "Owner".to_owned()])
    );

    // Se sincroniza a AveNode1 antes de emitir: los siguientes facts
    // exigen su compile remoto contra la gov_version actual, y la
    // distribución a testigos no forma parte del ciclo de la request.
    get_subject(eval_node, governance_id.clone(), Some(10), true)
        .await
        .unwrap();

    // SN 11: se añade un schema con contrato. La fase compile exige el
    // 2/2, así que AveNode1 compila por red; el commit también en
    // AveNode1 (testigo de la gov) prueba que aplica el evento con la
    // evidencia de compilación remota.
    let json = json!({
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
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(11), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 7);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);

    let state = get_subject(eval_node, governance_id.clone(), Some(11), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 7);
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    // SN 12: cambio solo de initial_value. Los compilers resuelven el
    // contrato actual contra su estado local (misma gov_version que la
    // request), sin que el contrato viaje por red.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_initial_value": {
                    "one": 10,
                    "two": 20,
                    "three": 30
                }
            }]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(12), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 8);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 10, "two": 20, "three": 30})
    );

    // AveNode1 tiene que estar al día antes del siguiente compile remoto.
    get_subject(eval_node, governance_id.clone(), Some(12), true)
        .await
        .unwrap();

    // SN 13 (fallido): cambiar el initial_value de un schema que no
    // existe. Los compilers votan InvalidEvent y el evento commitea
    // fallido sin pasar por evaluación: el sn avanza pero la versión y
    // los schemas no cambian, también en el testigo.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "NotASchema",
                "new_initial_value": {
                    "one": 1,
                    "two": 2,
                    "three": 3
                }
            }]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(13), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 8);
    assert_eq!(properties.schemas.len(), 1);
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["AveNode1".to_owned(), "Owner".to_owned()])
    );

    let state = get_subject(eval_node, governance_id.clone(), Some(13), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 8);
    assert_eq!(properties.schemas.len(), 1);

    // SN 14: cambio solo de contrato. El source viaja en el propio
    // evento (la rama que faltaba de resolve_compile_targets) y el
    // initial_value commiteado se mantiene intacto, como exige la
    // aplicación del evento. Cambiar al mismo valor sería un evento
    // inválido, así que se usa la otra versión del contrato de ejemplo
    // (misma forma de estado, distinto hash).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(14), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 9);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT_V2);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 10, "two": 20, "three": 30})
    );

    // AveNode1 tiene que estar al día antes del siguiente compile remoto.
    get_subject(eval_node, governance_id.clone(), Some(14), true)
        .await
        .unwrap();

    // SN 15: un solo evento añade dos schemas. La evidencia de compile
    // cubre varios contratos a la vez (mapa ordenado: si no fuese
    // determinista, los compilers firmarían resultados distintos y el
    // quórum no cerraría).
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example2",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Example3",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(15), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 10);
    assert_eq!(properties.schemas.len(), 3);
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example2".to_owned()))
    );
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example3".to_owned()))
    );

    let state = get_subject(eval_node, governance_id.clone(), Some(15), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 10);
    assert_eq!(properties.schemas.len(), 3);

    // SN 16: un mismo evento cambia un contrato y quita el rol compiler
    // a AveNode1. La fase compile se evalúa contra los roles ANTERIORES
    // al evento (quórum 2/2 con AveNode1 por red); tras el commit el set
    // de compilers queda reducido a {Owner}. El contrato vuelve a la
    // versión original (rollback).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT
            }]
        },
        "roles": {
            "governance": {
                "remove": {
                    "compiler": ["AveNode1"]
                }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(16), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 11);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        properties.roles_gov.compiler,
        BTreeSet::from(["Owner".to_owned()])
    );

    // SN 17: con el set reducido a {Owner} la fase compile sigue
    // funcionando 1/1 (cambio solo de initial_value), también aplicado
    // en AveNode1 como testigo.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_initial_value": {
                    "one": 100,
                    "two": 200,
                    "three": 300
                }
            }]
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(17), true)
            .await
            .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 12);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 100, "two": 200, "three": 300})
    );

    let state = get_subject(eval_node, governance_id.clone(), Some(17), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 12);
}
#[test(tokio::test)]
// Una request atascada en la fase de aprobación (aprobador caído, sin
// quórum) se puede abortar manualmente con limpieza: el manager para
// los hijos de la fase con reintentos de red en vuelo, registra el
// abort y la gobernanza no avanza.
async fn test_gov_approval_request_aborted_manually() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 pasa a ser aprobador y todo cambio de gobernanza
    // exige la aprobación de todos los aprobadores (fixed 100).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "approver": ["AveNode2"]
                }
            }
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la aprobación no puede cerrar el quórum: la
    // fase se queda reintentando el envío de red.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode3",
                    "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                        .public_key()
                        .to_string()
                }
            ]
        }
    });

    // El helper espera al estado Approval: la fase está en vuelo.
    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // El owner aprueba; solo falta AveNode2, que está caído.
    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    // Abort manual con la fase de aprobación en vuelo.
    node1
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id.clone(),
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    let aborts = get_abort_request(node1, governance_id.clone(), request_id)
        .await
        .unwrap();
    assert_eq!(aborts.events.len(), 1);
    assert_eq!(
        aborts.events[0].error,
        "The user manually aborted the request"
    );

    // La gobernanza no ha avanzado: sigue en el SN 1.
    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}
#[test(tokio::test)]
async fn test_delete_schema() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let json = json!({
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
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": 2
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );

    let json = json!({
        "schemas": {
            "remove": ["Example"]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    create_subject(node1, governance_id.clone(), "Example", "", true)
        .await
        .unwrap_err();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap_err();
    let state = get_subject(node1, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );
}
#[test(tokio::test)]
async fn test_change_schema() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let json = json!({
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
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": 2
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );

    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": CHANGED_SCHEMA_CONTRACT,
                "new_initial_value": {
                    "data": ""
                }
            }]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "ChangeData": {
            "data": "AveLedger",
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();
    let state = get_subject(node1, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({
            "data": "AveLedger"
        })
    );
}
#[test(tokio::test)]
// Definimos 2 validadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no
async fn test_gov_no_all_validators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "validator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    },
                    "compile": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
            "members": {
                "add": [
                    {
                        "name": "user",
                        "key": user
                    }
                ]
            },
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
            (
                "offline".to_owned(),
                PublicKey::from_str(&offline_controller).unwrap(),
            ),
            ("user".to_owned(), PublicKey::from_str(&user).unwrap()),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from(["Owner".to_owned()]),
            validator: BTreeSet::from([
                "Owner".to_owned(),
                "offline".to_owned(),
            ]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
            compile: Quorum::Fixed(1),
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
// Definimos 2 evaluadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no.
async fn test_gov_no_all_evaluators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
            "members": {
                "add": [
                    {
                        "name": "user",
                        "key": user
                    }
                ]
            },
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
            (
                "offline".to_owned(),
                PublicKey::from_str(&offline_controller).unwrap(),
            ),
            ("user".to_owned(), PublicKey::from_str(&user).unwrap()),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from([
                "Owner".to_owned(),
                "offline".to_owned(),
            ]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 2);
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
// Definimos 2 validadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no
// Algunos eventos fallan, por lo que la versión de la governanza no aumenta
async fn test_gov_fail_no_all_evaluators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let mut keys = vec![];
    for i in 0..2 {
        let user = if i % 2 != 0 {
            let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                .public_key()
                .to_string();

            keys.push(user.clone());

            user
        } else {
            String::default()
        };

        // add node bootstrap and ephemeral to governance
        let json = json!({
                "members": {
                    "add": [
                        {
                            "name": format!("user{}", i),
                            "key": user
                        }
                    ]
                },
        });

        emit_fact(owner_governance, governance_id.clone(), json, true)
            .await
            .unwrap();
    }

    let expected = GovernanceData {
        version: 2,
        members: BTreeMap::from([
            (
                "Owner".to_owned(),
                PublicKey::from_str(owner_governance.public_key()).unwrap(),
            ),
            (
                "offline".to_owned(),
                PublicKey::from_str(&offline_controller).unwrap(),
            ),
            ("user1".to_owned(), PublicKey::from_str(&keys[0]).unwrap()),
        ]),
        roles_gov: RolesGov {
            approver: BTreeSet::from(["Owner".to_owned()]),
            evaluator: BTreeSet::from([
                "Owner".to_owned(),
                "offline".to_owned(),
            ]),
            validator: BTreeSet::from(["Owner".to_owned()]),
            witness: BTreeSet::from(["Owner".to_owned()]),
            issuer: RoleGovIssuer {
                signers: BTreeSet::from(["Owner".to_owned()]),
                any: false,
            },
            compiler: BTreeSet::from(["Owner".to_owned()]),
        },
        policies_gov: PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Fixed(1),
            validate: Quorum::Fixed(1),
            compile: Quorum::Majority,
        },
        schemas: BTreeMap::new(),
        roles_schema: BTreeMap::new(),
        roles_tracker_schemas: RolesTrackerSchemas::default(),
        toolchain: GovernanceData::default().toolchain,
        policies_schema: BTreeMap::new(),
    };

    let state =
        get_subject(owner_governance, governance_id.clone(), Some(3), true)
            .await
            .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert!(state.active);
    assert_eq!(state.sn, 3);
    assert_governance_properties_eq(state.properties, expected);
}
#[test(tokio::test)]
async fn test_governance_schema_and_creator_viewpoints_state() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;

    let governance_id = create_and_authorize_governance(owner, vec![]).await;

    let alice = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": alice
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
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
                    "viewpoints": ["agua", "basura", "NoViewpoints"]
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 2
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

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let governance = governance_properties(state.properties);
    let schema_id = SchemaType::Type("Example".to_owned());

    assert_eq!(governance.version, 2);
    assert_eq!(
        governance.schemas.get(&schema_id).unwrap().viewpoints,
        BTreeSet::from([
            "NoViewpoints".to_owned(),
            "agua".to_owned(),
            "basura".to_owned(),
        ])
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
        BTreeSet::from([CreatorWitness {
            name: "Witnesses".to_owned(),
            viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
        }])
    );

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
                                        "name": "Witnesses",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "Alice",
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

    let state = get_subject(owner, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let governance = governance_properties(state.properties);
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
                name: "Witnesses".to_owned(),
                viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
            },
        ])
    );

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
                                        "name": "Witnesses",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "Alice",
                                        "viewpoints": ["NoViewpoints"]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        },
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_viewpoints": ["agua", "basura", "vidrio", "NoViewpoints"]
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
    let governance = governance_properties(state.properties);
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(governance.version, 4);
    assert_eq!(
        governance.schemas.get(&schema_id).unwrap().viewpoints,
        BTreeSet::from([
            "NoViewpoints".to_owned(),
            "agua".to_owned(),
            "basura".to_owned(),
            "vidrio".to_owned()
        ])
    );
    assert_eq!(
        creator.witnesses,
        BTreeSet::from([
            CreatorWitness {
                name: "Alice".to_owned(),
                viewpoints: BTreeSet::from(["NoViewpoints".to_owned()]),
            },
            CreatorWitness {
                name: "Witnesses".to_owned(),
                viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
            },
        ])
    );
}
#[test(tokio::test)]
async fn test_governance_invalid_viewpoints_validation() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;

    let governance_id = create_and_authorize_governance(owner, vec![]).await;

    let alice = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": alice
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
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
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "InvalidReserved",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    },
                    "viewpoints": ["AllViewpoints"]
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    let json = json!({
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
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 2
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
    let _ = get_subject(owner, governance_id.clone(), Some(4), true)
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
                                        "name": "Witnesses",
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
    let _ = get_subject(owner, governance_id.clone(), Some(5), true)
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
                                        "name": "Witnesses",
                                        "viewpoints": ["NoViewpoints"]
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
    let _ = get_subject(owner, governance_id.clone(), Some(6), true)
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
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(7), true)
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
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(8), true)
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
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    let _ = get_subject(owner, governance_id.clone(), Some(9), true)
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
                                        "name": "Owner",
                                        "viewpoints": ["agua"]
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
    let _ = get_subject(owner, governance_id.clone(), Some(10), true)
        .await
        .unwrap();

    let state = get_subject(owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    let governance = governance_properties(state.properties);
    let schema_id = SchemaType::Type("Example".to_owned());
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(governance.version, 2);
    assert_eq!(
        creator.witnesses,
        BTreeSet::from([CreatorWitness {
            name: "Witnesses".to_owned(),
            viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
        }])
    );
}
#[test(tokio::test)]
async fn test_sink_replay_and_external_db_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner = nodes[0].api.clone();
    let bob = nodes[1].api.clone();
    let bob_pk = PublicKey::from_str(bob.public_key()).unwrap();
    let charlie_pk =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    let invalid_member_pk =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&bob]).await;
    let governance_id_string = governance_id.to_string();

    let governance_setup_payload = json!({
        "members": {
            "add": [
                {
                    "name": "Bob",
                    "key": bob.public_key()
                },
                {
                    "name": "Charlie",
                    "key": charlie_pk.to_string()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Bob"]
                }
            }
        }
    });

    emit_fact(
        &owner,
        governance_id.clone(),
        governance_setup_payload.clone(),
        true,
    )
    .await
    .unwrap();

    get_subject(&bob, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    emit_fact(
        &owner,
        governance_id.clone(),
        governance_setup_payload.clone(),
        true,
    )
    .await
    .unwrap();

    emit_transfer(
        &owner,
        governance_id.clone(),
        invalid_member_pk.clone(),
        true,
    )
    .await
    .unwrap();

    emit_transfer(&owner, governance_id.clone(), bob_pk.clone(), true)
        .await
        .unwrap();

    get_subject(&bob, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    emit_confirm(
        &bob,
        governance_id.clone(),
        Some("Charlie".to_owned()),
        true,
    )
    .await
    .unwrap();

    emit_reject(&bob, governance_id.clone(), true)
        .await
        .unwrap();

    owner
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(bob_pk.clone()),
        )
        .await
        .unwrap();
    owner.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&owner, governance_id.clone(), Some(6), true)
        .await
        .unwrap();

    emit_eol(&owner, governance_id.clone(), true).await.unwrap();

    let subject_state =
        get_subject(&owner, governance_id.clone(), Some(7), true)
            .await
            .unwrap();
    assert!(!subject_state.active);

    let api_events = get_events(&owner, governance_id.clone(), 8, true)
        .await
        .unwrap();
    let sink_events = wait_sink_events(&owner, governance_id.clone(), 8)
        .await
        .unwrap();

    assert_eq!(api_events.len(), 8);
    assert_eq!(sink_events.len(), 8);

    match &api_events[0].event {
        RequestEventDB::Create {
            name,
            description,
            schema_id,
            namespace,
        } => {
            assert_eq!(name.as_deref(), Some("Governance Tests"));
            assert_eq!(
                description.as_deref(),
                Some("A description for Governance Tests")
            );
            assert_eq!(schema_id, "governance");
            assert_eq!(namespace, "");
        }
        other => panic!("unexpected create event: {other:?}"),
    }

    match &api_events[1].event {
        RequestEventDB::GovernanceFact {
            payload,
            evaluation_response,
            approval_success,
            compilation_response,
        } => {
            assert_eq!(payload, &governance_setup_payload);
            match evaluation_response {
                EvalResDB::Patch(_) => {}
                other => {
                    panic!("unexpected governance fact result: {other:?}")
                }
            }
            assert_eq!(*approval_success, Some(true));
            assert!(
                compilation_response.is_none(),
                "members/roles fact runs no compilation: {compilation_response:?}"
            );
        }
        other => panic!("unexpected governance fact event: {other:?}"),
    }

    match &api_events[2].event {
        RequestEventDB::GovernanceFact {
            payload,
            evaluation_response,
            approval_success,
            compilation_response,
        } => {
            assert_eq!(payload, &governance_setup_payload);
            match evaluation_response {
                EvalResDB::Error(error) => {
                    assert!(!error.is_empty());
                }
                other => {
                    panic!(
                        "unexpected failed governance fact result: {other:?}"
                    )
                }
            }
            assert!(approval_success.is_none());
            assert!(
                compilation_response.is_none(),
                "members/roles fact runs no compilation: {compilation_response:?}"
            );
        }
        other => panic!("unexpected failed governance fact event: {other:?}"),
    }

    match &api_events[3].event {
        RequestEventDB::Transfer {
            evaluation_error,
            new_owner,
        } => {
            assert_eq!(new_owner, &invalid_member_pk.to_string());
            assert!(evaluation_error.is_some());
        }
        other => panic!("unexpected failed transfer event: {other:?}"),
    }

    match &api_events[4].event {
        RequestEventDB::Transfer {
            evaluation_error,
            new_owner,
        } => {
            assert_eq!(new_owner, &bob.public_key());
            assert!(evaluation_error.is_none());
        }
        other => panic!("unexpected successful transfer event: {other:?}"),
    }

    match &api_events[5].event {
        RequestEventDB::GovernanceConfirm {
            name_old_owner,
            evaluation_response,
        } => {
            assert_eq!(name_old_owner.as_deref(), Some("Charlie"));
            match evaluation_response {
                EvalResDB::Error(error) => {
                    assert!(!error.is_empty());
                }
                other => panic!("unexpected failed confirm result: {other:?}"),
            }
        }
        other => panic!("unexpected failed confirm event: {other:?}"),
    }

    assert!(matches!(api_events[6].event, RequestEventDB::Reject));
    assert!(matches!(api_events[7].event, RequestEventDB::EOL));

    for event in &sink_events {
        assert!(event.event_request_timestamp > 0);
        assert!(event.event_ledger_timestamp > 0);
        assert!(event.sink_timestamp > 0);
    }

    match &sink_events[0].payload {
        DataToSinkEvent::Create {
            governance_id: event_governance_id,
            subject_id,
            owner: event_owner,
            schema_id,
            namespace,
            sn,
            gov_version,
            state,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(namespace, "");
            assert_eq!(*sn, 0);
            assert_eq!(*gov_version, 0);
            assert!(state.is_object());
        }
        other => panic!("unexpected sink create event: {other:?}"),
    }
    assert_eq!(sink_events[0].public_key, owner.public_key());

    match &sink_events[1].payload {
        DataToSinkEvent::FactFull {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            viewpoints,
            issuer,
            owner: event_owner,
            payload,
            patch,
            success,
            error,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert!(viewpoints.is_empty());
            assert_eq!(issuer, &owner.public_key());
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(payload, &governance_setup_payload);
            assert!(patch.is_some());
            assert!(*success);
            assert!(error.is_none());
            assert_eq!(*sn, 1);
            assert_eq!(*gov_version, 0);
        }
        other => panic!("unexpected sink successful fact event: {other:?}"),
    }
    assert_eq!(sink_events[1].public_key, owner.public_key());

    match &sink_events[2].payload {
        DataToSinkEvent::FactFull {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            viewpoints,
            issuer,
            owner: event_owner,
            payload,
            patch,
            success,
            error,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert!(viewpoints.is_empty());
            assert_eq!(issuer, &owner.public_key());
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(payload, &governance_setup_payload);
            assert!(patch.is_none());
            assert!(!success);
            assert!(error.is_some());
            assert_eq!(*sn, 2);
            assert_eq!(*gov_version, 1);
        }
        other => panic!("unexpected sink failed fact event: {other:?}"),
    }
    assert_eq!(sink_events[2].public_key, owner.public_key());

    match &sink_events[3].payload {
        DataToSinkEvent::Transfer {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            owner: event_owner,
            new_owner,
            success,
            error,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(new_owner, &invalid_member_pk.to_string());
            assert!(!success);
            assert!(error.is_some());
            assert_eq!(*sn, 3);
            assert_eq!(*gov_version, 1);
        }
        other => panic!("unexpected sink failed transfer event: {other:?}"),
    }
    assert_eq!(sink_events[3].public_key, owner.public_key());

    match &sink_events[4].payload {
        DataToSinkEvent::Transfer {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            owner: event_owner,
            new_owner,
            success,
            error,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(event_owner, &owner.public_key());
            assert_eq!(new_owner, &bob.public_key());
            assert!(*success);
            assert!(error.is_none());
            assert_eq!(*sn, 4);
            assert_eq!(*gov_version, 1);
        }
        other => panic!("unexpected sink successful transfer event: {other:?}"),
    }
    assert_eq!(sink_events[4].public_key, owner.public_key());

    match &sink_events[5].payload {
        DataToSinkEvent::Confirm {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            sn,
            patch,
            success,
            error,
            gov_version,
            name_old_owner,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(*sn, 5);
            assert!(patch.is_none());
            assert!(!success);
            assert!(error.is_some());
            assert_eq!(*gov_version, 2);
            assert_eq!(name_old_owner.as_deref(), Some("Charlie"));
        }
        other => panic!("unexpected sink failed confirm event: {other:?}"),
    }
    assert_eq!(sink_events[5].public_key, owner.public_key());

    match &sink_events[6].payload {
        DataToSinkEvent::Reject {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(*sn, 6);
            assert_eq!(*gov_version, 2);
        }
        other => panic!("unexpected sink reject event: {other:?}"),
    }
    assert_eq!(sink_events[6].public_key, owner.public_key());

    match &sink_events[7].payload {
        DataToSinkEvent::Eol {
            governance_id: event_governance_id,
            subject_id,
            schema_id,
            sn,
            gov_version,
        } => {
            assert!(event_governance_id.is_none());
            assert_eq!(subject_id, &governance_id_string);
            assert_eq!(schema_id, &SchemaType::Governance);
            assert_eq!(*sn, 7);
            assert_eq!(*gov_version, 3);
        }
        other => panic!("unexpected sink eol event: {other:?}"),
    }
    assert_eq!(sink_events[7].public_key, owner.public_key());
}
#[test(tokio::test)]
// test_build_batch_gov: Emisor construye batch de governance
//
// Qué se prueba:
//   `build_distribution_batch` para una governance. Verifica que el emisor
//   construye correctamente un batch de eventos de gobernanza (is_gov=true),
//   sin transfer_event, con los límites de gov_version aplicados.
//
// Setup:
//   1. Owner crea gobernanza con batch_size=2 (ledger_batch_size pequeño).
//   2. Owner emite 1 fact de config + 3 facts (SN llega a 4:
//      create SN=0 + config SN=1 + 3 facts SN=2..4).
//   3. Witness W1 se autoriza con owner y hace update_subject.
//   4. Verificar que W1 recibe TODOS los eventos (el batch se divide en
//      múltiples chunks porque batch_size=2 < total_events).
//   5. Verificar que W1 tiene el mismo SN que owner.
//
async fn test_build_batch_gov() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ledger_batch_size: Some(2),
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let witness = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![witness]).await;

    // Configurar gobernanza: añadir witness como witness y member
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": witness.public_key()
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Emitir más facts para crear múltiples SN
    for i in 1..=3 {
        let json = json!({
            "members": {
                "add": [
                    {
                        "name": format!("Fake{}", i),
                        "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                            .public_key()
                            .to_string()
                    }
                ]
            }
        });
        emit_fact(owner, governance_id.clone(), json, true)
            .await
            .unwrap();
    }

    // Witness se autoriza con owner como fuente
    witness
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    // Witness pide update → debe recibir todos los chunks
    witness.update_subject(governance_id.clone()).await.unwrap();

    // Verificar que witness tiene el mismo SN que owner (SN=5)
    get_subject(owner, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    get_subject(witness, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
}
#[test(tokio::test)]
// test_update_offer_gov: Receptor responde a GetLastSn con governance
//
// Qué se prueba:
//   `build_last_sn_offer` para una governance. Cuando un receptor solicita
//   el último SN de una governance, el emisor debe responder correctamente
//   con el SN, is_all, y los metadatos de gobernanza.
//
// Setup:
//   1. Owner crea gobernanza (SN=0).
//   2. Owner emite fact → SN=1.
//   3. Witness W1 se autoriza y hace update_subject → obtiene SN=1.
//   4. Owner emite más facts → SN avanza a 3.
//   5. W1 hace update_subject de nuevo → debe obtener SN=3.
//   6. Verificar que W1 siempre recibe el SN más alto ofrecido por owner.
//
async fn test_update_offer_gov() {
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

    // Configurar gobernanza: añadir witness como witness y member
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": witness.public_key()
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Witness se autoriza y obtiene SN=1
    witness
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    witness.update_subject(governance_id.clone()).await.unwrap();

    get_subject(witness, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Owner emite más facts → SN=2 y SN=3
    for i in 1..=2 {
        let json = json!({
            "members": {
                "add": [
                    {
                        "name": format!("Fake{}", i),
                        "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                            .public_key()
                            .to_string()
                    }
                ]
            }
        });
        emit_fact(owner, governance_id.clone(), json, true)
            .await
            .unwrap();
    }

    // Witness pide update de nuevo → debe llegar a SN=3
    witness.update_subject(governance_id.clone()).await.unwrap();

    get_subject(witness, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
}
#[test(tokio::test)]
// Wiping derived state is strictly worse than any crash window: if
// the boot replay heals a purged register back to the ledger tip, it
// heals any crash loss too.
async fn test_reconcile_heals_role_wipe() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();
    let node2 = nodes[1].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&node2]).await;

    let owner_key = PublicKey::from_str(node1.public_key()).unwrap();
    let node2_key = PublicKey::from_str(node2.public_key()).unwrap();

    // v1: add N2 as evaluator (both nodes live, so quorum votes arrive).
    // Fixed evaluation quorum: N2 must never be on the critical path
    // of later votes.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "N2",
                    "key": node2.public_key()
                }
            ]
        },
        "policies": {
            "governance": {
                "change": {
                    "evaluate": {
                        "fixed": 1
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": ["N2"],
                }
            }
        }
    });
    let request_id_v1 = emit_fact(&node1, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id_v1,
        true,
    )
    .await
    .unwrap();

    // v2: remove N2 (cascade drops its evaluator grant).
    let json = json!({
        "members": {
            "remove": ["N2"]
        }
    });
    let request_id_v2 = emit_fact(&node1, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id_v2,
        true,
    )
    .await
    .unwrap();

    // v3: re-add N2 as evaluator.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "N2",
                    "key": node2.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": ["N2"],
                }
            }
        }
    });
    let request_id_v3 = emit_fact(&node1, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id_v3,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 3);
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 3);
    assert!(properties.members.contains_key("N2"));

    let evaluators = node1
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert!(evaluators.contains(&owner_key));
    assert!(evaluators.contains(&node2_key));

    // Wipe derived state and reboot: the replay must converge back.
    node1
        .test_purge_register(governance_id.clone(), "role")
        .await
        .unwrap();

    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (new_node, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        keys: Some(nodes[0].keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut new_dirs);

    let api = new_node.api.clone();
    node_running(&api).await.unwrap();

    let state = get_subject(&api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 3);
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 3);
    assert!(properties.members.contains_key("N2"));

    let evaluators = api
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert!(evaluators.contains(&owner_key));
    assert!(evaluators.contains(&node2_key));

    node_running(&api).await.unwrap();
}
#[test(tokio::test)]
// Ownership rotation must survive derived-state loss: after wiping
// the registers and rebooting, the new owner is in charge and the
// old owner key holds no roles.
async fn test_reconcile_heals_rotation() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let future_owner = nodes[0].api.clone();
    let owner_governance = nodes[1].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner_governance, vec![&future_owner])
            .await;

    let old_key = PublicKey::from_str(owner_governance.public_key()).unwrap();
    let new_key = PublicKey::from_str(future_owner.public_key()).unwrap();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": future_owner.public_key()
                }
            ]
        },
            "roles": {
                "governance": {
                    "add": {
                        "witness": ["AveNode1"],
                        "compiler": ["AveNode1"],
                    }
                }
            }
    });
    emit_fact(&owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &owner_governance,
        governance_id.clone(),
        new_key.clone(),
        true,
    )
    .await
    .unwrap();

    emit_confirm(&future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();

    let state = get_subject(&future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.owner, future_owner.public_key());

    let evaluators = future_owner
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert!(evaluators.contains(&new_key));
    assert!(!evaluators.contains(&old_key));

    // Wipe rotation state and reboot the new owner.
    future_owner
        .test_purge_register(governance_id.clone(), "role")
        .await
        .unwrap();
    future_owner
        .test_purge_register(governance_id.clone(), "subject")
        .await
        .unwrap();
    future_owner
        .test_purge_register(governance_id.clone(), "witnesses")
        .await
        .unwrap();

    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (new_node, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        keys: Some(nodes[0].keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut new_dirs);

    let api = new_node.api.clone();
    node_running(&api).await.unwrap();

    let state = get_subject(&api, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(state.owner, future_owner.public_key());

    let evaluators = api
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert!(evaluators.contains(&new_key));
    assert!(!evaluators.contains(&old_key));

    node_running(&api).await.unwrap();
}
#[test(tokio::test)]
// A graceful shutdown marks the boot clean, so the reboot skips the
// replay and still converges: same ledger, same properties, same
// register state.
async fn test_clean_boot_skips_replay() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();

    let governance_id = create_and_authorize_governance(&node1, vec![]).await;

    let owner_key = PublicKey::from_str(node1.public_key()).unwrap();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "M1",
                    "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                        .public_key()
                        .to_string()
                }
            ]
        }
    });
    let request_id_f1 = emit_fact(&node1, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id_f1,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    let evaluators = node1
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert!(evaluators.contains(&owner_key));

    // Graceful-shutdown handshake, then reboot on the same stores.
    node1.prepare_clean_shutdown().await;
    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (new_node, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        keys: Some(nodes[0].keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut new_dirs);

    let api = new_node.api.clone();
    node_running(&api).await.unwrap();

    let state = get_subject(&api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(governance_properties(state.properties).version, 1);

    let evaluators = api
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert!(evaluators.contains(&owner_key));

    // The rebooted node accepts traffic: readiness flipped, so the
    // skip path reported instead of wedging the gate.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "M2",
                    "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                        .public_key()
                        .to_string()
                }
            ]
        }
    });
    let request_id_f2 = emit_fact(&api, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id_f2,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert_eq!(governance_properties(state.properties).version, 2);

    node_running(&api).await.unwrap();
}
#[test(tokio::test)]
// An in-flight request at shutdown completes after reboot, either
// way: applied before death (replay heals registers, resume finds
// nothing) or re-driven by resume (dirty replay plus deferred Run).
// Both branches converge on the same assertions.
async fn test_inflight_resume_after_reboot() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();

    let governance_id = create_and_authorize_governance(&node1, vec![]).await;

    let fake_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "M1",
                    "key": fake_key.to_string()
                }
            ]
        }
    });
    let request_id = emit_fact(&node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Wait until the handler registered the request: killing before
    // registration would leave nothing to resume or replay anywhere.
    for _ in 0..100 {
        if node1.get_request_state(request_id.clone()).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Vote without waiting, then wait until the vote lands (the
    // request leaves Approval): either the event applies before
    // death or resume plus replay complete it after reboot. Both
    // branches converge on the same assertions.
    emit_approve(
        &node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();
    for _ in 0..100 {
        let voted = node1
            .get_request_state(request_id.clone())
            .await
            .is_ok_and(|state| {
                !matches!(
                    state.state,
                    RequestState::InQueue
                        | RequestState::Handling
                        | RequestState::Approval
                )
            });
        if voted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (new_node, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        keys: Some(nodes[0].keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut new_dirs);

    let api = new_node.api.clone();
    node_running(&api).await.unwrap();

    // Barrier: a live register read queues behind governance
    // pre_start, so the assertions below observe post-boot state
    // instead of pre-reboot ext_db rows.
    let owner_key = PublicKey::from_str(node1.public_key()).unwrap();
    let evaluators = api
        .test_gov_evaluators(governance_id.clone())
        .await
        .unwrap();
    assert!(evaluators.contains(&owner_key));

    let state = get_subject(&api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 1);
    assert!(properties.members.contains_key("M1"));

    node_running(&api).await.unwrap();
}

#[test(tokio::test)]
// Change de contrato (Example A -> V2) como tercer fact de una
// gobernanza nueva con tracker y testigos: compila de verdad y
// commitea sn3. Presupuesto de 60s: si algo se atasca, el test
// falla en vez de colgar la suite.
async fn test_gov_change_contract_with_tracker_and_witnesses() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (node1, mut dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            always_accept: true,
            ..Default::default()
        })
        .await;
        node_running(&node1.api).await.unwrap();
        let peer1 = RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        };
        let (node2, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![peer1.clone()],
            always_accept: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&node2.api).await.unwrap();
        let (node3, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![peer1],
            always_accept: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&node3.api).await.unwrap();

        let owner = &node1.api;
        let witness = &node2.api;

        let governance_id =
            create_and_authorize_governance(owner, vec![witness]).await;

        // sn1: miembro + schema Example (A) + testigo de gobernanza.
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": witness.public_key()}]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2"]}},
            },
        });
        emit_fact(owner, governance_id.clone(), json, true).await.unwrap();
        let _ = get_subject(owner, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

        // sn2: roles del schema (owner evalua y valida, testigo observa).
        let json = json!({
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "AveNode2", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "AveNode2", "namespace": []}],
                },
            }]},
        });
        emit_fact(owner, governance_id.clone(), json, true).await.unwrap();
        let _ = get_subject(owner, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

        // Tracker del owner con un fact: hay ledger vivo bajo la gov.
        let (tracker_id, ..) =
            create_subject(owner, governance_id.clone(), "Example", "", true)
                .await
                .unwrap();
        emit_fact(owner, tracker_id.clone(), json!({"ModOne": {"data": 10}}), true)
            .await
            .unwrap();
        let _ = get_subject(owner, tracker_id.clone(), Some(1), true)
            .await
            .unwrap();

        // sn3: change Example A -> V2, commitea sn3.
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2,
            }]},
        });
        emit_fact(owner, governance_id.clone(), json, true).await.unwrap();
        let state = get_subject(owner, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
        assert_eq!(state.sn, 3);
        let gov = governance_properties(state.properties);
        assert_eq!(gov.version, 3);

        // El contrato que corre es V2: acepta three = 50.
        emit_fact(owner, tracker_id.clone(), json!({"ModThree": {"data": 50}}), true)
            .await
            .unwrap();
        let state = get_subject(owner, tracker_id.clone(), Some(2), true)
            .await
            .unwrap();
        assert_eq!(state.properties, json!({"one": 10, "two": 0, "three": 50}));

        // El testigo tambien ve sn3: la distribucion no depende
        // de su voto.
        let state = get_subject(witness, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
        assert_eq!(state.sn, 3);

        node_running(owner).await.unwrap();
        node_running(witness).await.unwrap();
        node_running(&node3.api).await.unwrap();
    })
    .await
    .expect("test overran its 60s budget");
}

#[test(tokio::test)]
// Change con dos approvers (Owner + AveNode2, votan los dos):
// el change compila V2 y commitea sn3. Presupuesto de 60s: si
// algo se atasca, el test falla en vez de colgar la suite.
async fn test_gov_change_with_two_approvers() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (node1, mut dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            always_accept: true,
            ..Default::default()
        })
        .await;
        node_running(&node1.api).await.unwrap();
        let peer1 = RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        };
        let (node2, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![peer1.clone()],
            always_accept: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&node2.api).await.unwrap();
        let (node3, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![peer1],
            always_accept: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&node3.api).await.unwrap();

        let owner = &node1.api;
        let witness = &node2.api;

        let governance_id =
            create_and_authorize_governance(owner, vec![witness]).await;

        // sn1: miembro + schema Example (A) + testigo de gobernanza.
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": witness.public_key()}]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2"]}},
            },
        });
        emit_fact(owner, governance_id.clone(), json, true).await.unwrap();
        let _ = get_subject(owner, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

        // sn2: roles del schema + AveNode2 como approver de gobernanza.
        let json = json!({
            "roles": {
                "governance": {"add": {"approver": ["AveNode2"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {"name": "Owner", "namespace": [], "quantity": "infinity"},
                            {"name": "AveNode2", "namespace": [], "quantity": "infinity"},
                        ],
                        "issuer": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "AveNode2", "namespace": []}],
                    },
                }],
            },
        });
        emit_fact(owner, governance_id.clone(), json, true).await.unwrap();
        let _ = get_subject(owner, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

        // Tracker del owner con un fact.
        let (tracker_id, ..) =
            create_subject(owner, governance_id.clone(), "Example", "", true)
                .await
                .unwrap();
        emit_fact(owner, tracker_id.clone(), json!({"ModOne": {"data": 10}}), true)
            .await
            .unwrap();
        let _ = get_subject(owner, tracker_id.clone(), Some(1), true)
            .await
            .unwrap();

        // sn3: change Example A -> V2. Votan los dos approvers
        // (aceptacion automatica) y commitea sn3.
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2,
            }]},
        });
        emit_fact(owner, governance_id.clone(), json, true).await.unwrap();
        let state = get_subject(owner, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
        assert_eq!(state.sn, 3);

        node_running(owner).await.unwrap();
        node_running(witness).await.unwrap();
        node_running(&node3.api).await.unwrap();
    })
    .await
    .expect("test overran its 60s budget");
}

#[test(tokio::test)]
// Change con restart del owner en mitad del vuelo: el change
// debe recuperarse y commitear sn3. Presupuesto de 60s: si la
// recuperacion se atasca, el test falla en vez de colgar.
async fn test_gov_change_with_owner_restart_midflight() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let contracts_dir = tempfile::tempdir().unwrap();
        let (mut node1, mut dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            always_accept: true,
            contracts_path: Some(contracts_dir.path().to_path_buf()),
            ..Default::default()
        })
        .await;
        node_running(&node1.api).await.unwrap();
        let peer1 = RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        };
        let (node2, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![peer1],
            always_accept: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&node2.api).await.unwrap();
        let peer2 = RoutingNode {
            peer_id: node2.api.peer_id().to_string(),
            address: vec![node2.listen_address.clone()],
        };

        let owner_key = node1.keys.clone();
        let owner_api = node1.api.clone();
        let witness_api = node2.api.clone();

        let governance_id =
            create_and_authorize_governance(&owner_api, vec![&witness_api])
                .await;

        // sn1: miembro + schema Example (A) + testigo de gobernanza.
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": witness_api.public_key()}]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2"]}},
            },
        });
        emit_fact(&owner_api, governance_id.clone(), json, true)
            .await
            .unwrap();
        let _ = get_subject(&owner_api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

        // sn2: roles del schema.
        let json = json!({
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "AveNode2", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "AveNode2", "namespace": []}],
                },
            }]},
        });
        emit_fact(&owner_api, governance_id.clone(), json, true)
            .await
            .unwrap();
        let _ = get_subject(&owner_api, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

        // sn3: change Example A -> V2 sin espera y restart
        // inmediato del owner: la request sigue en vuelo seguro.
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2,
            }]},
        });
        emit_fact(&owner_api, governance_id.clone(), json, false)
            .await
            .unwrap();

        node1.token.cancel();
        join_all(node1.handler.iter_mut()).await;

        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (new_node, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!("/memory/{port}"),
            peers: vec![peer2],
            always_accept: true,
            keys: Some(owner_key),
            local_db: Some(dirs[0].path().to_path_buf()),
            ext_db: Some(dirs[1].path().to_path_buf()),
            contracts_path: Some(contracts_dir.path().to_path_buf()),
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);

        let api = new_node.api.clone();
        node_running(&api).await.unwrap();

        // La request se recupera y el change commitea sn3.
        let state = get_subject(&api, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
        assert_eq!(state.sn, 3);
        let gov = governance_properties(state.properties);
        assert_eq!(gov.version, 3);

        node_running(&api).await.unwrap();
        node_running(&witness_api).await.unwrap();
    })
    .await
    .expect("test overran its 60s budget");
}

#[test(tokio::test)]
// Change a contrato invalido (base64 truncado): aborta sin
// dejar evento y el siguiente schema-add commitea. Presupuesto
// de 60s: si el add posterior se atasca tras el abort, el test
// falla en vez de colgar.
async fn test_gov_invalid_change_aborts_and_next_add_commits() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (node1, mut dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            always_accept: true,
            ..Default::default()
        })
        .await;
        node_running(&node1.api).await.unwrap();
        let peer1 = RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        };
        let (node2, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![peer1],
            always_accept: false,
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&node2.api).await.unwrap();

        let owner = node1.api.clone();
        let witness = node2.api.clone();

        let governance_id =
            create_and_authorize_governance(&owner, vec![&witness]).await;

        // sn1: miembro + schema Example (A) + testigo de gobernanza.
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": witness.public_key()}]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2"]}},
            },
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
        let _ = get_subject(&owner, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

        // sn2: roles del schema.
        let json = json!({
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "AveNode2", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "AveNode2", "namespace": []}],
                },
            }]},
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
        let _ = get_subject(&owner, governance_id.clone(), Some(2), true)
            .await
            .unwrap();

        // Change a contrato invalido: aborta, no deja sn.
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": INVALID_EXAMPLE_CONTRACT,
            }]},
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();

        // El siguiente add (Third) commitea como sn3: el abort
        // no atasca la gobernanza.
        let json = json!({
            "schemas": {"add": [{
                "id": "Third",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
            }]},
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
        let state = get_subject(&owner, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
        assert_eq!(state.sn, 3);
        let gov = governance_properties(state.properties);
        assert!(gov.schemas.contains_key(&SchemaType::Type("Third".to_owned())));

        node_running(&owner).await.unwrap();
        node_running(&witness).await.unwrap();
    })
    .await
    .expect("test overran its 60s budget");
}

#[test(tokio::test)]
// Salto de gov_version con fallidas en medio: el tracker emite,
// la gov avanza (change ok, dos fallidas que congelan version,
// dos miembros) y el tracker vuelve a emitir bajo la version
// nueva. Presupuesto de 60s.
async fn test_gov_version_skip_with_failures_in_between() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (node1, mut dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            always_accept: true,
            ..Default::default()
        })
        .await;
        node_running(&node1.api).await.unwrap();
        let peer1 = RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        };
        let (node2, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![peer1],
            always_accept: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&node2.api).await.unwrap();

        let owner = node1.api.clone();
        let witness = node2.api.clone();

        let governance_id =
            create_and_authorize_governance(&owner, vec![&witness]).await;

        // sn1: miembro + schema Example (A) + testigo.
        let json = json!({
            "members": {"add": [{"name": "AveNode2", "key": witness.public_key()}]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
            "roles": {
                "governance": {"add": {"witness": ["AveNode2"]}},
            },
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
        let state =
            get_subject(&owner, governance_id.clone(), Some(1), true)
                .await
                .unwrap();
        assert_eq!(governance_properties(state.properties).version, 1);

        // sn2: roles del schema.
        let json = json!({
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "AveNode2", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "AveNode2", "namespace": []}],
                },
            }]},
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
        let state =
            get_subject(&owner, governance_id.clone(), Some(2), true)
                .await
                .unwrap();
        assert_eq!(governance_properties(state.properties).version, 2);

        // Tracker + fact bajo v2.
        let (tracker_id, ..) =
            create_subject(&owner, governance_id.clone(), "Example", "", true)
                .await
                .unwrap();
        emit_fact(&owner, tracker_id.clone(), json!({"ModOne": {"data": 10}}), true)
            .await
            .unwrap();
        let _ = get_subject(&owner, tracker_id.clone(), Some(1), true)
            .await
            .unwrap();

        // sn3: change A -> V2 (v2 -> v3).
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2,
            }]},
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
        let state =
            get_subject(&owner, governance_id.clone(), Some(3), true)
                .await
                .unwrap();
        assert_eq!(governance_properties(state.properties).version, 3);

        // sn4: change a schema inexistente (falla, congela v3).
        let json = json!({
            "schemas": {"change": [{
                "actual_id": "NotASchema",
                "new_initial_value": {"one": 1},
            }]},
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
        let state =
            get_subject(&owner, governance_id.clone(), Some(4), true)
                .await
                .unwrap();
        assert_eq!(
            governance_properties(state.properties).version,
            3,
            "failed event must freeze the version"
        );

        // sn5: add duplicado (falla, congela v3).
        let json = json!({
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua", "basura"],
            }]},
        });
        emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
        let state =
            get_subject(&owner, governance_id.clone(), Some(5), true)
                .await
                .unwrap();
        assert_eq!(
            governance_properties(state.properties).version,
            3,
            "failed event must freeze the version"
        );

        // Dos miembros (v3 -> v4 -> v5).
        for name in ["Charlie", "Dave"] {
            let member_key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                .public_key()
                .to_string();
            let json = json!({
                "members": {"add": [{"name": name, "key": member_key}]},
            });
            emit_fact(&owner, governance_id.clone(), json, true)
                .await
                .unwrap();
        }
        let state =
            get_subject(&owner, governance_id.clone(), Some(7), true)
                .await
                .unwrap();
        assert_eq!(governance_properties(state.properties).version, 5);

        // El tracker vuelve a emitir: corre V2 bajo v5 (salto
        // v2 -> v5 con dos fallidas en medio).
        emit_fact(&owner, tracker_id.clone(), json!({"ModOne": {"data": 11}}), true)
            .await
            .unwrap();
        let state = get_subject(&owner, tracker_id.clone(), Some(2), true)
            .await
            .unwrap();
        assert_eq!(state.properties, json!({"one": 11, "two": 0, "three": 0}));
        // V2 acepta three = 50 (A lo rechaza).
        emit_fact(&owner, tracker_id.clone(), json!({"ModThree": {"data": 50}}), true)
            .await
            .unwrap();
        let state = get_subject(&owner, tracker_id.clone(), Some(3), true)
            .await
            .unwrap();
        assert_eq!(state.properties, json!({"one": 11, "two": 0, "three": 50}));

        node_running(&owner).await.unwrap();
        node_running(&witness).await.unwrap();
    })
    .await
    .expect("test overran its 60s budget");
}

/// End-to-end for report item 45: a schema id with path separators
/// must change nothing. The event itself is recorded like any failed
/// event (sn advances), but the hostile id never lands in state, so
/// it can never reach staging/artifact paths. The compiler refuses
/// it before building (`resolve_compile_targets` votes `Error`, no
/// cargo runs) and a refused compilation skips evaluation straight
/// to validation; the join sites fail closed on top. This suite runs
/// `always_accept` (auto-approval ignores verdicts), so what the
/// test asserts is the state after commit — no schema added —
/// while a valid schema still lands (rejection poisons nothing).
/// Walks this process' test contracts roots and fails on any path
/// carrying the hostile marker: with the fix, a refused schema never
/// reaches staging or artifact directories.
fn assert_no_hostile_artifacts() {
    let prefix = format!("ave-test-contracts-{}-", std::process::id());
    let mut roots = vec![];
    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                roots.push(entry.path());
            }
        }
    }
    assert!(
        !roots.is_empty(),
        "expected test contracts roots under the temp dir"
    );
    let mut stack = roots;
    while let Some(path) = stack.pop() {
        let name = path.to_string_lossy().into_owned();
        assert!(
            !name.contains("outside"),
            "hostile artifact escaped contracts root: {name}"
        );
        if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&path) {
                stack.extend(entries.flatten().map(|e| e.path()));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_schema_id_fails_without_state_change() {
    tokio::time::timeout(Duration::from_secs(300), async {
        let (nodes, _dirs) =
            create_nodes_and_connections(CreateNodesAndConnectionsConfig {
                bootstrap: vec![vec![]],
                always_accept: true,
                ..Default::default()
            })
            .await;
        let owner = &nodes[0].api;

        let governance_id =
            create_and_authorize_governance(owner, vec![]).await;

        // Would escape `contracts_path` if ever joined into a
        // staging/artifact name.
        let hostile = json!({
            "schemas": {
                "add": [
                    {
                        "id": "x/../../outside",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {
                            "one": 0,
                            "two": 0,
                            "three": 0
                        }
                    }
                ]
            },
        });
        let request_id =
            emit_fact(owner, governance_id.clone(), hostile, false)
                .await
                .unwrap();
        wait_request(owner, request_id).await.unwrap();

        // The event is recorded like any failed event (sn advances),
        // but the state must not change: no schema added.
        let state = get_subject(owner, governance_id.clone(), None, true)
            .await
            .unwrap();
        assert_eq!(state.sn, 1, "the failed event is still recorded");
        let gov = governance_properties(state.properties.clone());
        assert!(
            gov.schemas.is_empty(),
            "hostile schema id must change nothing, got {:?}",
            gov.schemas
                .keys()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );

        // The compiler refused it before touching the filesystem: no
        // staging or artifact directory for the hostile id may exist
        // anywhere under this process' contracts roots (a full
        // pre-fix run left `/tmp/outside_<hash>/` with compiled wasm
        // behind — that is the escape this test guards).
        assert_no_hostile_artifacts();

        // Never usable: no tracker can be created under it.
        create_subject(
            owner,
            governance_id.clone(),
            "x/../../outside",
            "",
            false,
        )
        .await
        .expect_err("tracker under a rejected schema id must fail");

        // Item 42: a dot is path-safe but not actor-safe. The schema
        // id is valid for governance and passes the filesystem gate,
        // yet no `{id}_contract_compiler` / `{id}_evaluation` /
        // `{id}_validation` actor can ever be created for it, so the
        // compiler refuses it the same way: recorded, no state
        // change, no tracker, node stays healthy.
        let dotted = json!({
            "schemas": {
                "add": [
                    {
                        "id": "orders.v1",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {
                            "one": 0,
                            "two": 0,
                            "three": 0
                        }
                    }
                ]
            },
        });
        let request_id = emit_fact(owner, governance_id.clone(), dotted, false)
            .await
            .unwrap();
        wait_request(owner, request_id).await.unwrap();
        let state = get_subject(owner, governance_id.clone(), None, true)
            .await
            .unwrap();
        assert_eq!(state.sn, 2, "the refused event is still recorded");
        let gov = governance_properties(state.properties.clone());
        assert!(
            gov.schemas.is_empty(),
            "dotted schema id must change nothing, got {:?}",
            gov.schemas
                .keys()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        create_subject(owner, governance_id.clone(), "orders.v1", "", false)
            .await
            .expect_err("tracker under a dotted schema id must fail");

        // The node stays healthy: a valid schema still lands.
        let valid = json!({
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
        });
        let request_id = emit_fact(owner, governance_id.clone(), valid, false)
            .await
            .unwrap();
        wait_request(owner, request_id.clone()).await.unwrap();
        let terminal = owner.get_request_state(request_id).await.unwrap().state;
        assert!(
            matches!(terminal, RequestState::Finish),
            "valid schema must still apply, got {terminal:?}"
        );
        let state = get_subject(owner, governance_id.clone(), None, true)
            .await
            .unwrap();
        let gov = governance_properties(state.properties.clone());
        assert!(
            gov.schemas
                .contains_key(&SchemaType::Type("Example".to_owned())),
            "valid schema must persist after hostile refusal"
        );
    })
    .await
    .expect("test overran its 300s budget");
}

/// Approvals listing covers every governance with stable paging
/// (BR22-01): the per-governance fan-out runs in parallel instead of
/// holding the central handler for the whole sweep, but the collected
/// set is identical and pages follow the same order. Bounded by
/// timeout: the listing must answer even with a slow approver.
#[test(tokio::test)]
async fn approvals_listing_covers_all_governances_paged() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let (mut nodes, dirs) =
            create_nodes_and_connections(CreateNodesAndConnectionsConfig {
                bootstrap: vec![vec![]],
                addressable: vec![vec![0]],
                always_accept: true,
                ..Default::default()
            })
            .await;
        let owner = nodes[0].api.clone();
        let alice = nodes[1].api.clone();

        for _ in 0..2 {
            let governance_id =
                create_and_authorize_governance(&owner, vec![&alice]).await;
            let config = json!({
                "members": {"add": [{
                    "name": "Alice",
                    "key": alice.public_key(),
                }]},
                "schemas": {"add": [{
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0},
                }]},
                "roles": {
                    "governance": {
                        "add": {"witness": ["Alice"]},
                    },
                    "schema": [{
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [
                                {"name": "Owner", "namespace": []}
                            ],
                            "validator": [
                                {"name": "Owner", "namespace": []}
                            ],
                            "creator": [{
                                "name": "Alice",
                                "namespace": [],
                                "quantity": "infinity",
                            }],
                            "issuer": [{
                                "name": "Alice",
                                "namespace": [],
                            }],
                        },
                    }],
                },
            });
            emit_fact(&owner, governance_id.clone(), config, true)
                .await
                .unwrap();
            let gov_sn = get_subject(&owner, governance_id.clone(), None, true)
                .await
                .unwrap()
                .sn;
            alice.update_subject(governance_id.clone()).await.unwrap();
            get_subject(&alice, governance_id.clone(), Some(gov_sn), true)
                .await
                .unwrap();
            create_subject(&alice, governance_id, "Example", "", true)
                .await
                .unwrap();
        }

        // One stored approval per governance, same set on repeat
        // calls, pages split it without loss or reorder.
        let full = owner.get_approvals(None, 10, 0).await.unwrap();
        assert_eq!(full.len(), 2);
        let again = owner.get_approvals(None, 10, 0).await.unwrap();
        assert_eq!(
            full.iter()
                .map(|item| item.request_id.clone())
                .collect::<Vec<_>>(),
            again
                .iter()
                .map(|item| item.request_id.clone())
                .collect::<Vec<_>>(),
        );
        let first = owner.get_approvals(None, 1, 0).await.unwrap();
        let second = owner.get_approvals(None, 1, 1).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].request_id, full[0].request_id);
        assert_eq!(second[0].request_id, full[1].request_id);

        for node in nodes.iter_mut() {
            node.token.cancel();
        }
        join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut()))
            .await;
        drop(nodes);
        drop(dirs);
    })
    .await
    .expect("approvals listing hung");
}

// Auth governance copies are supervised to the offered
// SN. Single witness, no periodic sync to mask the fault.
#[test(tokio::test)]
async fn gov_copy_auth_req_lost_retries_to_tip() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    for name in ["A", "B", "C", "D"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    let state = get_subject(&learner, governance_id.clone(), Some(tip), true)
        .await
        .unwrap();
    assert_eq!(state.sn, tip);
    let held = learner.test_held_outbound().await.unwrap();
    let held_reqs = held
        .iter()
        .filter(|m| {
            matches!(&m.message, ActorMessage::DistributionLedgerReq { .. })
        })
        .count();
    assert_eq!(held_reqs, 1, "first request must stay held, copy via retry");

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

// Lost first ledger response is retried to the tip.
#[test(tokio::test)]
async fn gov_copy_auth_res_lost_retries_to_tip() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    for name in ["A", "B", "C", "D"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerRes,
            peer: Some(learner_key.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    let state = get_subject(&learner, governance_id.clone(), Some(tip), true)
        .await
        .unwrap();
    assert_eq!(state.sn, tip);
    let held = owner.test_held_outbound().await.unwrap();
    let held_res = held
        .iter()
        .filter(|m| {
            matches!(&m.message, ActorMessage::DistributionLedgerRes { .. })
        })
        .count();
    assert_eq!(held_res, 1, "first response must stay held, copy via retry");

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

// Authentic prefix with premature is_all is partial,
// the copy continues to the offered tip once real traffic flows.
#[test(tokio::test)]
async fn gov_copy_premature_is_all_treated_as_partial() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    for name in ["A", "B", "C", "D", "E", "F"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    assert!(tip >= 6, "need a multi-batch tip, got {tip}");

    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerRes,
            peer: Some(learner_key.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();

    let mut prefix = Vec::new();
    for sn in 0..=2 {
        prefix.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    learner
        .test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver: learner_key.clone(),
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger: prefix,
                    is_all: true,
                    transfer_event: None,
                    expected_governance_id: Some(governance_id.clone()),
                },
            ),
            &owner_key,
        )
        .await
        .unwrap();
    get_subject(&learner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    // The tip being visible only proves the apply: wait until the
    // copy attempt itself closes, so the no-acquisition verdict below
    // is read after the fallback decision ran, never before it.
    for _ in 0..300 {
        if learner.test_active_attempts_len().await.unwrap_or(1) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        learner.test_active_attempts_len().await.unwrap(),
        0,
        "the refused batch must leave no attempt in flight"
    );
    for _ in 0..30 {
        assert_eq!(
            learner
                .test_deferred_acquisition_count(governance_id.clone())
                .await
                .unwrap(),
            0,
            "deferred acquisition stays blocked below the offered tip"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    owner.test_clear_faults().await.unwrap();
    let state = get_subject(&learner, governance_id.clone(), Some(tip), true)
        .await
        .unwrap();
    assert_eq!(state.sn, tip);
    let start = tokio::time::Instant::now();
    loop {
        let count = learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap();
        if count >= 1 {
            assert_eq!(count, 1, "certified tip triggers acquisition once");
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "certified tip never triggered deferred acquisition"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

// Control: prefix with is_all false continues normally to the tip.
#[test(tokio::test)]
async fn gov_copy_partial_is_all_false_continues_to_tip() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    for name in ["A", "B", "C", "D", "E", "F"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerRes,
            peer: Some(learner_key.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();

    let mut prefix = Vec::new();
    for sn in 0..=2 {
        prefix.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    learner
        .test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver: learner_key.clone(),
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger: prefix,
                    is_all: false,
                    transfer_event: None,
                    expected_governance_id: Some(governance_id.clone()),
                },
            ),
            &owner_key,
        )
        .await
        .unwrap();
    get_subject(&learner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    owner.test_release_held().await.unwrap();
    let state = get_subject(&learner, governance_id.clone(), Some(tip), true)
        .await
        .unwrap();
    assert_eq!(state.sn, tip);

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

// Termination by ledger SN, not properties.version.
// Trailing failed events freeze the version while the SN advances;
// the supervised copy must still reach the SN tip.
#[test(tokio::test)]
async fn gov_copy_failed_events_terminate_by_sn_not_version() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(PublicKey::from_str(learner.public_key()).unwrap()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    let key_a = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({"members": {"add": [{"name": "A", "key": key_a}]}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    // Two trailing failures: unknown schema change and duplicate add.
    // Both record SN without moving properties.version.
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({"schemas": {"change": [{
            "actual_id": "NotASchema",
            "new_initial_value": {"one": 1},
        }]}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &owner,
        governance_id.clone(),
        serde_json::json!({"schemas": {"add": [{
            "id": "Example",
            "contract": EXAMPLE_CONTRACT,
            "initial_value": {"one": 0, "two": 0, "three": 0},
        }]}}),
        true,
    )
    .await
    .unwrap();

    let owner_state = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    let tip = owner_state.sn;
    let version = governance_properties(owner_state.properties).version;
    assert!(
        tip > version,
        "trailing failures must split SN {tip} from version {version}"
    );

    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    let learner_state =
        get_subject(&learner, governance_id.clone(), Some(tip), true)
            .await
            .unwrap();
    assert_eq!(learner_state.sn, tip);
    assert_eq!(
        governance_properties(learner_state.properties).version,
        version,
    );
    let held = learner.test_held_outbound().await.unwrap();
    let held_reqs = held
        .iter()
        .filter(|m| {
            matches!(&m.message, ActorMessage::DistributionLedgerReq { .. })
        })
        .count();
    assert_eq!(held_reqs, 1, "first request must stay held, copy via retry");

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// The periodic version sync must notice a trailing failed event:
/// the peer answers the same version with a higher ledger tip, so
/// the learner fetches from its own SN instead of certifying idle.
/// The wire keeps the old version-only answer and adds an explicit
/// version-plus-tip answer; a lower version alone never fetches.
#[test(tokio::test)]
async fn governance_sync_discovers_failed_event_with_unchanged_version() {
    assert_eq!(
        NetworkMessage::required_wire_version(
            &ActorMessage::GovernanceVersionRes { version: 1 }
        ),
        1,
        "the legacy version-only answer stays a v1 message"
    );
    assert_eq!(
        NetworkMessage::required_wire_version(
            &ActorMessage::GovernanceVersionResV2 { version: 1, sn: 2 }
        ),
        2,
        "the version-plus-tip answer is an explicit v2 message"
    );

    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    // No pushes to the learner from here on: the trailing failure
    // must arrive through the periodic version sync, never seeded.
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    let synced = get_subject(&learner, governance_id.clone(), None, true)
        .await
        .unwrap();
    let version = governance_properties(synced.properties).version;
    let base_sn = synced.sn;

    // A trailing failure records SN without moving the version.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({"schemas": {"change": [{
            "actual_id": "NotASchema",
            "new_initial_value": {"one": 1},
        }]}}),
        true,
    )
    .await
    .unwrap();
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    assert_eq!(tip, base_sn + 1, "the failure must extend the tip by one");
    assert_eq!(
        governance_properties(
            get_subject(&owner, governance_id.clone(), None, true)
                .await
                .unwrap()
                .properties
        )
        .version,
        version,
        "the failure must leave the version unchanged"
    );

    // The next periodic round answers the same version with a higher
    // tip, so the learner pulls from its own SN and converges.
    let advanced =
        get_subject(&learner, governance_id.clone(), Some(tip), true)
            .await
            .unwrap();
    assert_eq!(advanced.sn, tip);
    assert_eq!(
        governance_properties(advanced.properties).version,
        version,
        "converging on a failure must not move the version"
    );

    // One full sync round of stability: equal-or-behind peers fetch
    // nothing and move neither tip nor version. Hold every new pull so
    // the assertion measures requests, not merely a lack of SN changes.
    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let state = get_subject(&learner, governance_id.clone(), None, true)
            .await
            .unwrap();
        assert_eq!(state.sn, tip, "no spurious fetch past the tip");
        assert_eq!(
            governance_properties(state.properties).version,
            version,
            "no spurious version move at the tip"
        );
    }
    let spurious = learner
        .test_held_outbound()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|message| {
            matches!(
                message.message,
                ActorMessage::DistributionLedgerReq { .. }
            )
        })
        .count();
    assert_eq!(spurious, 0, "an idle round must not fetch again");

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// Waits until this node parked an exhausted `Auth` retry round,
/// polling observable barrier state with a bounded budget instead
/// of timing assumptions.
async fn wait_update_retry_exhausted(api: &Api) {
    for _ in 0..450 {
        if api
            .test_update_retry_exhausted_hold_count()
            .await
            .unwrap_or(0)
            >= 1
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no supervised retry round ever parked at exhaustion");
}

/// Waits until the deferred acquisition trigger count reaches at
/// least `want`, polling observable registry state with a bounded
/// budget instead of timing assumptions.
async fn wait_deferred_count(
    api: &Api,
    governance_id: DigestIdentifier,
    want: u64,
) {
    for _ in 0..300 {
        if api
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap_or(0)
            >= want
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Reads the newest round among this node's held ledger requests:
/// retries advance the generation, so the maximum names the live
/// supervised round.
async fn newest_held_request_round(api: &Api) -> u64 {
    let mut round = 0u64;
    for _ in 0..300 {
        let mut seen = false;
        for message in api.test_held_outbound().await.unwrap_or_default() {
            if let ActorMessage::DistributionLedgerReq { .. } = message.message
            {
                seen = true;
                round = round.max(message.info.version);
            }
        }
        if seen {
            return round;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no held ledger request names the live round");
}

/// Injects an authentic governance batch as a complete response,
/// addressed to the node-level distributor like any pull response.
async fn inject_gov_batch(
    api: &Api,
    from: &PublicKey,
    governance_id: DigestIdentifier,
    ledger: Vec<Ledger>,
    is_all: bool,
    round: u64,
) {
    let receiver =
        PublicKey::from_str(api.public_key()).expect("node public key");
    let message = NetworkMessage::new(
        ComunicateInfo {
            request_id: String::new(),
            version: round,
            receiver,
            receiver_actor: "/user/node/distributor".to_owned(),
        },
        ActorMessage::DistributionLedgerRes {
            ledger,
            is_all,
            transfer_event: None,
            expected_governance_id: Some(governance_id),
        },
    );
    api.test_inject_inbound(message, from).await.unwrap();
}

/// A `DistributionDone` accepted before the stop must still certify
/// the tip: the exhausted `Auth` round parks, the final response is
/// applied and enqueued, and releasing the stop drains the completion
/// into exactly one deferred acquisition.
#[test(tokio::test)]
async fn gov_copy_distribution_done_survives_retry_exhaustion_stop() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            update_sync: Some(fast_update_sync()),
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();
    // No pushes to the learner from here on: it must stay empty so
    // every sweep below is a genuine pull with a live request.
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    for name in ["A", "B", "C", "D"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    assert!(
        learner
            .get_subject_state(governance_id.clone())
            .await
            .is_err(),
        "the learner starts empty so no prior acquisition exists"
    );

    // Every ledger request stays held: retries keep firing while no
    // response ever lands, until the last retry round parks.
    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner
        .test_pause_update_retry_exhausted(true)
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    wait_update_retry_exhausted(&learner).await;
    let round = newest_held_request_round(&learner).await;

    // The final response carries the live round: applying it enqueues
    // the completion before the stop runs.
    let mut ledger = Vec::new();
    for sn in 0..=tip {
        ledger.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    inject_gov_batch(
        &learner,
        &owner_key,
        governance_id.clone(),
        ledger,
        true,
        round,
    )
    .await;
    get_subject(&learner, governance_id.clone(), Some(tip), true)
        .await
        .unwrap();
    learner
        .test_pause_update_retry_exhausted(false)
        .await
        .unwrap();

    wait_deferred_count(&learner, governance_id.clone(), 1).await;
    assert_eq!(
        learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap(),
        1,
        "the drained completion certifies the tip exactly once"
    );
    assert!(
        !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "the certified round stops instead of lingering"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// Same exhausted-round race with a previous-generation batch: the
/// round parks after reading a short tip, the final batch lands with
/// the older generation and the stop drains its completion. The tip
/// already covers the target, so the stale completion must certify
/// exactly once instead of being dropped silently. Non-service
/// nodes have no periodic idle to repair the markers.
#[test(tokio::test)]
async fn gov_copy_stale_generation_done_certifies_reached_target() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            update_sync: Some(fast_update_sync()),
            is_service: false,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();
    // No pushes to the learner from here on: it must stay empty so
    // every sweep below is a genuine pull with a live request.
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    for name in ["A", "B", "C", "D"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    assert!(
        learner
            .get_subject_state(governance_id.clone())
            .await
            .is_err(),
        "the learner starts empty so no prior acquisition exists"
    );

    // Every ledger request stays held: retries keep firing while no
    // response ever lands, until the last retry round parks.
    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner
        .test_pause_update_retry_exhausted(true)
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    wait_update_retry_exhausted(&learner).await;
    let round = newest_held_request_round(&learner).await;
    assert!(
        round >= 1,
        "a previous generation must exist, got round {round}"
    );

    // The final batch lands with the previous generation: applying it
    // reaches the tip, but its completion is stale for the live
    // round. The re-check must still certify exactly once.
    let mut ledger = Vec::new();
    for sn in 0..=tip {
        ledger.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    inject_gov_batch(
        &learner,
        &owner_key,
        governance_id.clone(),
        ledger,
        true,
        round - 1,
    )
    .await;
    get_subject(&learner, governance_id.clone(), Some(tip), true)
        .await
        .unwrap();
    learner
        .test_pause_update_retry_exhausted(false)
        .await
        .unwrap();

    wait_deferred_count(&learner, governance_id.clone(), 1).await;
    assert_eq!(
        learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap(),
        1,
        "the stale completion must certify the reached tip exactly once"
    );
    assert!(
        !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "the certified round stops instead of lingering"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// Same race through the manual catch-up round: no `Auth` update
/// exists, so only the `gov_manual_update` path can certify the tip
/// and run the single deferred acquisition.
#[test(tokio::test)]
async fn gov_copy_distribution_done_survives_retry_exhaustion_stop_manual() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            update_sync: Some(fast_update_sync()),
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    // The learner syncs the first version through a normal round so
    // the manual catch-up below starts behind with a live governance.
    // That sync already certifies one deferred acquisition.
    learner.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&learner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(
        learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap(),
        1,
        "the setup sync certifies exactly one acquisition"
    );
    for name in ["A", "B", "C", "D"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    assert!(
        !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "no auth round may certify this copy"
    );

    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner
        .test_pause_update_retry_exhausted(true)
        .await
        .unwrap();
    learner
        .test_trigger_gov_update(governance_id.clone())
        .await
        .unwrap();
    wait_update_retry_exhausted(&learner).await;
    let round = newest_held_request_round(&learner).await;

    // The final batch starts past the locally applied tip: an
    // overlap would be dropped as a stale head instead of applying.
    let local_sn = get_subject(&learner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    let mut ledger = Vec::new();
    for sn in local_sn + 1..=tip {
        ledger.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    inject_gov_batch(
        &learner,
        &owner_key,
        governance_id.clone(),
        ledger,
        true,
        round,
    )
    .await;
    get_subject(&learner, governance_id.clone(), Some(tip), true)
        .await
        .unwrap();
    learner
        .test_pause_update_retry_exhausted(false)
        .await
        .unwrap();

    // The stop is the completion proof: only after the round is gone
    // may the count be read as final, never right after the release.
    for _ in 0..300 {
        if !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "no auth round lingers behind the manual one"
    );
    wait_deferred_count(&learner, governance_id.clone(), 2).await;
    assert_eq!(
        learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap(),
        2,
        "the drained completion certifies the tip exactly once more"
    );
    for _ in 0..30 {
        assert_eq!(
            learner
                .test_deferred_acquisition_count(governance_id.clone())
                .await
                .unwrap(),
            2,
            "the drained completion certifies exactly once"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// A premature completion below the supervised target certifies
/// nothing: the round keeps waiting, no deferred acquisition runs,
/// and releasing the exhausted stop still runs none.
#[test(tokio::test)]
async fn gov_copy_premature_target_done_is_ignored() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            update_sync: Some(fast_update_sync()),
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    for name in ["A", "B", "C", "D", "E"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Every ledger request stays held so the supervised round never
    // completes on its own; it must reach its retry budget parked.
    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner
        .test_pause_update_retry_exhausted(true)
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    wait_update_retry_exhausted(&learner).await;
    let round = newest_held_request_round(&learner).await;

    // A complete-looking batch below the offered tip must not
    // certify: the round stays alive and nothing is acquired, even
    // though the generation matches and would stop the actor.
    let mut ledger = Vec::new();
    for sn in 0..tip {
        ledger.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    inject_gov_batch(
        &learner,
        &owner_key,
        governance_id.clone(),
        ledger,
        true,
        round,
    )
    .await;
    get_subject(&learner, governance_id.clone(), Some(tip - 1), true)
        .await
        .unwrap();
    assert!(
        learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "a premature completion must not stop the supervised round"
    );
    assert_eq!(
        learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap(),
        0,
        "no acquisition runs before the supervised tip"
    );

    // Releasing the exhausted stop still acquires nothing: the only
    // queued completion stayed below the target, and no supervisor
    // remains to run anything else afterwards.
    learner
        .test_pause_update_retry_exhausted(false)
        .await
        .unwrap();
    assert_eq!(
        learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap(),
        0,
        "stopping below the target acquires nothing"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// An unsupervised governance copy still runs its deferred pass
/// exactly once through the direct fallback. `UpdateType::Request`
/// rounds live under `/user/request` and are never told
/// `DistributionDone` (only the auth and manual paths are), so this
/// fallback is the only acquisition they can ever trigger.
#[test(tokio::test)]
async fn gov_copy_unsupervised_completion_runs_deferred_fallback() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    for name in ["A", "B"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        emit_fact(
            &owner,
            governance_id.clone(),
            serde_json::json!({"members": {"add": [{"name": name, "key": key}]}}),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // No update round of any kind runs here: the injected batch must
    // complete through the unsupervised fallback alone.
    assert!(
        !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "no supervised round may certify this copy"
    );
    let mut ledger = Vec::new();
    for sn in 0..=tip {
        ledger.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    inject_gov_batch(
        &learner,
        &owner_key,
        governance_id.clone(),
        ledger,
        true,
        0,
    )
    .await;
    get_subject(&learner, governance_id.clone(), Some(tip), true)
        .await
        .unwrap();

    wait_deferred_count(&learner, governance_id.clone(), 1).await;
    assert_eq!(
        learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap(),
        1,
        "the unsupervised copy acquires exactly once via fallback"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// A late answer of a dead supervised round below its target must not
/// run the unsupervised fallback: no deferred acquisition, markers
/// kept, serving still blocked. The deferred pass clears markers and
/// opens the serving gate together, so markers conserved plus an
/// unchanged trigger count proves the gate never opened.
#[test(tokio::test)]
async fn gov_copy_late_supervised_below_target_never_acquires() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            update_sync: Some(fast_update_sync()),
            is_service: false,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    // The learner first converges to this member-only tip through a
    // normal supervised round, so the later schema window applies as
    // an update (deferred markers) instead of a fresh creation.
    let base = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    learner.update_subject(governance_id.clone()).await.unwrap();
    for _ in 0..300 {
        match get_subject(&learner, governance_id.clone(), Some(base), true)
            .await
        {
            Ok(_) => break,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    get_subject(&learner, governance_id.clone(), Some(base), true)
        .await
        .unwrap();
    for _ in 0..300 {
        if !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // A contract window so the catch-up defers artifact work: the
    // partial apply below must leave pending markers behind. The
    // learner never votes on these facts: SN2 compiles with the
    // owner alone, and SN3 grants the compiler role together with
    // the change, so its compile still uses the pre-event compilers.
    // A behind compiler would answer Unavailable and stall the emit.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "roles": {
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {"name": "Owner", "namespace": [], "quantity": 10}
                        ],
                        "issuer": [{"name": "Owner", "namespace": []}],
                    },
                }],
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {
                            "one": 0,
                            "two": 0,
                            "three": 0,
                        }
                    }
                ]
            },
        }),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "roles": {
                "governance": {
                    "add": {"compiler": ["Learner"]}
                }
            },
            "schemas": {
                "change": [{
                    "actual_id": "Example",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    // A trailing member fact moves the tip past the schema window so
    // the late batch below can name a real target above it.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{
                "name": "Extra",
                "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                    .public_key()
                    .to_string(),
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    let tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Every ledger request stays held so the supervised round never
    // completes on its own; it must reach its retry budget parked.
    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    learner
        .test_pause_update_retry_exhausted(true)
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    wait_update_retry_exhausted(&learner).await;
    let round = newest_held_request_round(&learner).await;

    // Let the parked round die uncertified: the supervisor records
    // its generation and stops.
    learner
        .test_pause_update_retry_exhausted(false)
        .await
        .unwrap();
    for _ in 0..300 {
        if !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "the exhausted round stops without certifying below the target"
    );
    // The dead-round record travels by fire-and-forget tell: wait
    // for it with a bounded poll so the late batch provably meets
    // the gate under test instead of racing it.
    for _ in 0..300 {
        if learner
            .test_has_dead_supervised_round(governance_id.clone(), round)
            .await
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        learner
            .test_has_dead_supervised_round(governance_id.clone(), round)
            .await
            .unwrap_or(false),
        "the dead round must be recorded before the late batch arrives"
    );

    // Baseline before the late stimulus: phase one certified its
    // own tip, so the deferred trigger count may already be nonzero;
    // what matters is that the late batch adds nothing.
    let base_count = learner
        .test_deferred_acquisition_count(governance_id.clone())
        .await
        .unwrap();
    // The late batch names the dead generation and claims
    // completeness, but only reaches below the offered tip. It
    // starts at the learner's tip: an older head would be discarded
    // as stale (`EnsureNextSn`) instead of exercising the fallback
    // gate under test.
    let mut ledger = Vec::new();
    for sn in (base + 1)..tip {
        ledger.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    inject_gov_batch(
        &learner,
        &owner_key,
        governance_id.clone(),
        ledger,
        true,
        round,
    )
    .await;
    // The batch applies (the learner reaches below the tip) but
    // must not certify: the supervisor is gone and the generation
    // is recorded dead, so the unsupervised fallback stays off.
    get_subject(&learner, governance_id.clone(), Some(tip - 1), true)
        .await
        .unwrap();

    // The fallback would clear markers and bump the count
    // asynchronously: poll a bounded budget, failing fast if it
    // ever fires, so a settled read is not rushed. The late batch
    // must add nothing on top of the phase-one baseline.
    for _ in 0..30 {
        assert_eq!(
            learner
                .test_deferred_acquisition_count(governance_id.clone())
                .await
                .unwrap(),
            base_count,
            "a late supervised answer below its target never acquires"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !learner
            .test_governance_pending_acquisitions(governance_id.clone())
            .await
            .unwrap()
            .is_empty(),
        "the late batch below the target keeps its deferred markers"
    );
    assert!(
        !learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "no supervisor is resurrected by the late batch"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// Mixed-kind offers pin the subject type: the first selected offer fixes
/// the subject kind and extends the target only over same-kind
/// offers. A higher opposite-kind offer must not inflate the
/// request, and a stale completion between the two targets neither
/// certifies nor acquires. Both pin directions are covered: a
/// tracker update pinned by preference over a higher governance
/// offer, and a governance update pinned while a higher tracker
/// offer sits in the map without covering the next SN.
#[test(tokio::test)]
async fn gov_copy_mixed_kind_offers_pin_subject_type() {
    // Held ledger requests of one node as (receiver, actual,
    // target, round): the round pins which supervised generation
    // emitted each request.
    async fn held_reqs(
        api: &Api,
        subject: &DigestIdentifier,
    ) -> Vec<(PublicKey, Option<u64>, Option<u64>, u64)> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| match m.message {
                ActorMessage::DistributionLedgerReq {
                    actual_sn,
                    target_sn,
                    subject_id,
                    ..
                } if subject_id == *subject => Some((
                    m.info.receiver,
                    actual_sn,
                    target_sn,
                    m.info.version,
                )),
                _ => None,
            })
            .collect()
    }

    // Injects a crafted offer as if `from` had answered the sweep in
    // `round`: the updater only accepts its own witness, so the rogue
    // must name a swept peer.
    async fn inject_offer(
        api: &Api,
        from: &PublicKey,
        subject: &DigestIdentifier,
        witness: &PublicKey,
        round: u64,
        offer: &UpdateWitnessOffer,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).unwrap();
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: format!(
                        "/user/node/auth/{subject}/{witness}_{round}"
                    ),
                },
                ActorMessage::UpdateOffer {
                    offer: offer.clone(),
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    // Polls until the learner holds requests for `subject`, then
    // asserts every supervised round requested exactly once, to an
    // expected witness, for the pinned target. Retries repeat the
    // same single request per generation; a duplicate or inflated
    // fetch inside one round fails here.
    async fn assert_pinned_requests(
        api: &Api,
        subject: &DigestIdentifier,
        allowed: &[(&str, PublicKey)],
        actual: Option<u64>,
        target: u64,
    ) -> u64 {
        let mut seen_rounds = BTreeSet::new();
        for _ in 0..300 {
            for (to, req_actual, req_target, round) in
                held_reqs(api, subject).await
            {
                let who = allowed
                    .iter()
                    .find(|(_, key)| *key == to)
                    .map(|(name, _)| *name)
                    .unwrap_or("unexpected");
                assert_eq!(
                    req_target,
                    Some(target),
                    "every round must request the pinned target, got {req_target:?} to {to:?} ({who})"
                );
                assert_eq!(
                    who, "owner",
                    "the request must go to the same-kind witness, got {to:?} ({who})"
                );
                assert_eq!(
                    req_actual, actual,
                    "the request must carry the requester tip"
                );
                assert_eq!(
                    req_target,
                    Some(target),
                    "every round must request the pinned target, got {req_target:?} to {to:?}"
                );
                seen_rounds.insert(round);
            }
            if !seen_rounds.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!seen_rounds.is_empty(), "the pinned round must request");
        let mut per_round: BTreeMap<u64, usize> = BTreeMap::new();
        for (_, _, _, round) in held_reqs(api, subject).await {
            *per_round.entry(round).or_default() += 1;
        }
        assert!(
            per_round.values().all(|count| *count == 1),
            "every round must emit exactly one request, got {per_round:?}"
        );
        seen_rounds.iter().last().copied().unwrap_or(0)
    }

    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let w1 = nodes[1].api.clone();
    let learner = nodes[2].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();
    let w1_key = PublicKey::from_str(w1.public_key()).unwrap();
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&w1, &learner]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [
                {"name": "W1", "key": w1.public_key()},
                {"name": "Learner", "key": learner.public_key()},
            ]},
            "roles": {
                "governance": {"add": {"witness": ["W1", "Learner"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [{
                            "name": "Owner",
                            "namespace": [],
                            "quantity": "infinity",
                            "witnesses": [
                                {"name": "W1", "viewpoints": ["agua"]},
                                {"name": "Learner", "viewpoints": ["agua"]},
                            ],
                        }],
                        "issuer": [{"name": "Owner", "namespace": []}],
                    },
                }],
            },
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
                "viewpoints": ["agua"],
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    let gov_tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    w1.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w1, governance_id.clone(), Some(gov_tip), true)
        .await
        .unwrap();

    // No pushes to the learner while the calendar builds: it must
    // start empty so both updates below are genuine pulls with live
    // requests, never pre-seeded state. Dropping the last-event
    // handshake blocks pushes at their trigger, and dropping ledger
    // batches blocks direct pushes; the witness empty-mapping test
    // proves the handshake part. Background version and tracker
    // syncs stay off the learner too, so its tips only move through
    // the driven updates below.
    for api in [&owner, &w1] {
        for message in [
            FaultMessage::DistributionLastEventReq,
            FaultMessage::DistributionLastEventRes,
            FaultMessage::DistributionLedgerRes,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    for message in [
        FaultMessage::GovernanceVersionReq,
        FaultMessage::TrackerSyncReq,
    ] {
        learner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // Tracker subject both witnesses pull; the learner stays empty so
    // both updates below start without a kind hint.
    let (subject_id, _) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1, 2, 3] {
        emit_fact_viewpoints(
            &owner,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            BTreeSet::from(["agua".to_string()]),
            true,
        )
        .await
        .unwrap();
    }
    let tip = get_subject(&owner, subject_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    assert_eq!(tip, 3, "three facts plus the create");
    w1.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&w1, subject_id.clone(), Some(tip), true)
        .await
        .unwrap();
    assert!(
        learner.get_subject_state(subject_id.clone()).await.is_err(),
        "the learner starts with no tracker data"
    );
    learner
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    // The learner's requests stay held so every supervised round
    // parks with a live request to read.
    learner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // Direction one: tracker pinned by preference over a higher
    // governance rogue. w1 joins the sweep as a sync peer; its real
    // offer is dropped so its only response is the rogue, while the
    // owner answers with the genuine tracker offer. The rogue lands
    // in milliseconds against the updater's five-second timeout, so
    // the selection below runs with both kinds mapped; w1 could only
    // answer with the rogue.
    learner
        .add_sync_peer(subject_id.clone(), vec![w1_key.clone()])
        .await
        .unwrap();
    for message in [FaultMessage::UpdateOffer, FaultMessage::UpdateNoOffer] {
        w1.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: None,
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    learner.update_subject(subject_id.clone()).await.unwrap();
    let mut w1_rounds = Vec::new();
    for _ in 0..300 {
        w1_rounds = learner
            .test_update_updater_rounds(subject_id.clone(), w1_key.clone())
            .await
            .unwrap_or_default();
        if !w1_rounds.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !w1_rounds.is_empty(),
        "w1 must be swept for the mixed offers to meet"
    );
    inject_offer(
        &learner,
        &w1_key,
        &subject_id,
        &w1_key,
        *w1_rounds.iter().max().unwrap(),
        &UpdateWitnessOffer {
            kind: UpdateSubjectKind::Governance,
            sn: tip + 10,
            clear_sn: None,
            ranges: Vec::new(),
        },
    )
    .await;
    let round = assert_pinned_requests(
        &learner,
        &subject_id,
        &[("owner", owner_key.clone()), ("w1", w1_key.clone())],
        None,
        tip,
    )
    .await;
    // A stale completion between the two targets certifies nothing:
    // the tip never reached the pinned target. Baseline first: only
    // the Done below may move the count, and it must not.
    let base_count = learner
        .test_deferred_acquisition_count(governance_id.clone())
        .await
        .unwrap();
    learner
        .test_update_done(subject_id.clone(), tip + 5, round + 1)
        .await
        .unwrap();
    assert!(
        learner.test_update_alive(subject_id.clone()).await.unwrap(),
        "the between-targets completion must not stop the round"
    );
    for _ in 0..30 {
        assert_eq!(
            learner
                .test_deferred_acquisition_count(governance_id.clone())
                .await
                .unwrap(),
            base_count,
            "the between-targets completion must not acquire"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Direction two: governance pinned while a higher tracker rogue
    // sits in the map without covering the next SN. The learner
    // stays behind on purpose: a fresh governance fact moves the tip
    // past its snapshot, so the genuine offer below still counts
    // while the rogue above the tip can never cover the next SN.
    // w1's real offer is dropped so its only response is the rogue.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{
                "name": "Extra",
                "key": KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                    .public_key()
                    .to_string(),
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    let gov_tip = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    w1.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w1, governance_id.clone(), Some(gov_tip), true)
        .await
        .unwrap();
    let learner_gov_sn = learner
        .get_subject_state(governance_id.clone())
        .await
        .map(|state| state.sn)
        .ok();
    learner
        .add_sync_peer(governance_id.clone(), vec![w1_key.clone()])
        .await
        .unwrap();
    learner.update_subject(governance_id.clone()).await.unwrap();
    let mut w1_rounds = Vec::new();
    for _ in 0..300 {
        w1_rounds = learner
            .test_update_updater_rounds(governance_id.clone(), w1_key.clone())
            .await
            .unwrap_or_default();
        if !w1_rounds.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !w1_rounds.is_empty(),
        "w1 must be swept for the mixed offers to meet"
    );
    inject_offer(
        &learner,
        &w1_key,
        &governance_id,
        &w1_key,
        *w1_rounds.iter().max().unwrap(),
        &UpdateWitnessOffer {
            kind: UpdateSubjectKind::Tracker,
            sn: gov_tip + 10,
            clear_sn: None,
            ranges: vec![TrackerDeliveryRange {
                from_sn: gov_tip + 10,
                to_sn: gov_tip + 10,
                mode: TrackerDeliveryMode::Clear,
            }],
        },
    )
    .await;
    let round = assert_pinned_requests(
        &learner,
        &governance_id,
        &[("owner", owner_key.clone()), ("w1", w1_key.clone())],
        learner_gov_sn,
        gov_tip,
    )
    .await;
    learner
        .test_update_done(governance_id.clone(), gov_tip + 5, round + 1)
        .await
        .unwrap();
    assert!(
        learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap(),
        "the between-targets completion must not stop the round"
    );
    let base_count = learner
        .test_deferred_acquisition_count(governance_id.clone())
        .await
        .unwrap();
    for _ in 0..30 {
        let count = learner
            .test_deferred_acquisition_count(governance_id.clone())
            .await
            .unwrap();
        let tip = learner
            .get_subject_state(governance_id.clone())
            .await
            .map(|s| s.sn);
        let alive = learner
            .test_update_alive(governance_id.clone())
            .await
            .unwrap();
        assert_eq!(
            count, base_count,
            "the between-targets completion must not acquire (tip={tip:?}, alive={alive})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// A partial governance creation never confirms: a failed step
/// reports its error and drops a fresh child, so the retry resumes
/// instead of accepting an unregistered child. The same holds for a
/// tracker creation retry.
#[test(tokio::test)]
async fn partial_governance_create_is_resumed_not_confirmed() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let learner = nodes[1].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&learner]).await;
    let learner_key = PublicKey::from_str(learner.public_key()).unwrap();
    // No pushes to the learner from here on: every creation below
    // must go through the explicit Ups, never seeded.
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(learner_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{"name": "Learner", "key": learner.public_key()}]},
            "roles": {"governance": {"add": {"witness": ["Learner"]}}},
        }),
        true,
    )
    .await
    .unwrap();
    let genesis = owner
        .test_get_ledger_event(governance_id.clone(), 0)
        .await
        .unwrap();

    // Sink failure first: nothing is confirmed and nothing stays
    // behind to confirm later.
    learner.test_arm_fail_next_sink().await.unwrap();
    let err = learner
        .test_up_subject_with_create(governance_id.clone(), genesis.clone())
        .await
        .expect_err("a failed sink setup must not confirm the creation");
    assert!(
        format!("{err:?}").contains("injected sink setup failure"),
        "the sink fault must surface, got {err:?}"
    );
    assert!(
        !learner
            .test_node_has_subject(governance_id.clone())
            .await
            .unwrap(),
        "no partial governance may be registered in Node"
    );
    assert!(
        !learner
            .test_has_live_subject_actor(governance_id.clone())
            .await,
        "no fresh child may linger after the failed sink setup"
    );

    // Registration failure next: genesis already landed, but the
    // creation still reports its error instead of confirming a
    // missing registration.
    learner.test_arm_fail_next_node_register().await.unwrap();
    let err = learner
        .test_up_subject_with_create(governance_id.clone(), genesis.clone())
        .await
        .expect_err("a failed registration must not confirm the creation");
    assert!(
        format!("{err:?}").contains("injected node registration failure"),
        "the register fault must surface, got {err:?}"
    );
    assert!(
        !learner
            .test_node_has_subject(governance_id.clone())
            .await
            .unwrap(),
        "no partial governance may be registered in Node"
    );
    assert!(
        !learner
            .test_has_live_subject_actor(governance_id.clone())
            .await,
        "no fresh child may linger after the failed registration"
    );

    // Cleanup finishes before the error returns, so the very next
    // attempt never reuses a dying child or needs a timing retry.
    learner
        .test_up_subject_with_create(governance_id.clone(), genesis.clone())
        .await
        .unwrap();
    assert!(
        learner
            .test_node_has_subject(governance_id.clone())
            .await
            .unwrap(),
        "the resumed creation must register in Node, not just externally"
    );
    assert!(
        learner
            .test_has_live_subject_actor(governance_id.clone())
            .await,
        "the resumed creation must run on a live child"
    );
    let state = get_subject(&learner, governance_id.clone(), Some(0), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 0, "the resumed creation lands genesis");

    // Tracker creations resume the same way: a failed sink setup
    // never confirms, and the retry completes. The learner syncs
    // governance to the tip first, so the tracker genesis validates
    // against the schema roles.
    learner.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&learner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    // The owner needs an explicit creator role first (harness member
    // names are reused when present).
    let gov_state = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    let members = governance_properties(gov_state.properties).members.clone();
    let owner_name = members
        .iter()
        .find_map(|(name, key)| {
            (key.to_string() == owner.public_key()).then(|| name.clone())
        })
        .unwrap_or_else(|| "Holder".to_owned());
    let mut member_adds = vec![];
    if !members
        .values()
        .any(|key| key.to_string() == owner.public_key())
    {
        member_adds.push(json!({"name": "Holder", "key": owner.public_key()}));
    }
    let mut schema_fact = json!({
        "schemas": {"add": [{
            "id": "Example",
            "contract": EXAMPLE_CONTRACT,
            "initial_value": {"one": 0, "two": 0, "three": 0},
        }]},
        "roles": {"schema": [{
            "schema_id": "Example",
            "add": {
                "evaluator": [{"name": "Owner", "namespace": []}],
                "validator": [{"name": "Owner", "namespace": []}],
                "creator": [{
                    "name": owner_name,
                    "namespace": [],
                    "quantity": "infinity",
                    "witnesses": [],
                }],
                "issuer": [{"name": owner_name, "namespace": []}],
            },
        }]},
    });
    if !member_adds.is_empty() {
        schema_fact["members"] = json!({"add": member_adds});
    }
    emit_fact(&owner, governance_id.clone(), schema_fact, true)
        .await
        .unwrap();
    let gov_state = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap();
    let gov_version = governance_properties(gov_state.properties).version;
    assert!(
        gov_version >= 1,
        "the schema/roles fact must apply, got version {gov_version}"
    );
    learner.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&learner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let subject_id =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap()
            .0;
    let tracker_genesis = owner
        .test_get_tracker_ledger(subject_id.clone(), 0)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 0)
        .expect("tracker genesis must exist");
    learner.test_arm_fail_next_sink().await.unwrap();
    let err = learner
        .test_up_subject_with_create(
            subject_id.clone(),
            tracker_genesis.clone(),
        )
        .await
        .expect_err(
            "a failed tracker sink setup must not confirm the creation",
        );
    assert!(
        format!("{err:?}").contains("injected sink setup failure"),
        "the sink fault must surface, got {err:?}"
    );
    assert!(
        !learner
            .test_node_has_subject(subject_id.clone())
            .await
            .unwrap(),
        "no partial tracker may be registered in Node"
    );
    assert!(
        !learner
            .test_has_live_subject_actor(subject_id.clone())
            .await,
        "no fresh child may linger after the failed tracker sink setup"
    );

    // Registration failure, tracker side: genesis already landed,
    // but the creation reports its error instead of confirming a
    // missing registration.
    learner.test_arm_fail_next_node_register().await.unwrap();
    let err = learner
        .test_up_subject_with_create(
            subject_id.clone(),
            tracker_genesis.clone(),
        )
        .await
        .expect_err(
            "a failed tracker registration must not confirm the creation",
        );
    assert!(
        format!("{err:?}").contains("injected node registration failure"),
        "the register fault must surface, got {err:?}"
    );
    assert!(
        !learner
            .test_node_has_subject(subject_id.clone())
            .await
            .unwrap(),
        "no partial tracker may be registered in Node"
    );
    assert!(
        !learner
            .test_has_live_subject_actor(subject_id.clone())
            .await,
        "no fresh child may linger after the failed tracker registration"
    );
    learner
        .test_up_subject_with_create(
            subject_id.clone(),
            tracker_genesis.clone(),
        )
        .await
        .unwrap();
    assert!(
        learner
            .test_node_has_subject(subject_id.clone())
            .await
            .unwrap(),
        "the resumed tracker must register in Node, not just externally"
    );
    assert!(
        learner
            .test_has_live_subject_actor(subject_id.clone())
            .await,
        "the resumed tracker must run on a live child"
    );
    get_subject(&learner, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}
