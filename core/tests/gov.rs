use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::atomic::Ordering,
};

mod common;

use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    bridge::{
        request::ApprovalStateRes,
        response::{EvalResDB, RequestEventDB},
    },
    identity::{
        PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
    response::RequestState,
    sink::DataToSinkEvent,
};
use ave_core::auth::AuthWitness;
use ave_core::governance::data::GovernanceData;
use ave_core::governance::model::{
    CreatorWitness, PolicyGov, PolicySchema, Quorum, RoleCreator,
    RoleGovIssuer, RolesGov, RolesSchema, RolesTrackerSchemas, Schema,
};

use ave_network::{NodeType, RoutingNode};
use common::{
    CHANGED_SCHEMA_CONTRACT, CreateNodeConfig,
    CreateNodesAndConnectionsConfig, EXAMPLE_CONTRACT, EXAMPLE_CONTRACT_V2,
    assert_governance_properties_eq, create_and_authorize_governance,
    create_nodes_and_connections, create_subject, emit_approve,
    emit_confirm, emit_eol, emit_fact, emit_reject, emit_transfer,
    get_events, get_subject, governance_properties, wait_sink_events,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    PORT_COUNTER, create_node, get_abort_request, node_running,
    wait_request_state,
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
        policies_schema: BTreeMap::new(),
    };
    assert_governance_properties_eq(state.properties, expected);
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

    let transfer_data = owner_governance.get_pending_transfers().await.unwrap();
    assert_eq!(
        transfer_data[0].actual_owner.to_string(),
        owner_governance.public_key()
    );
    assert_eq!(
        transfer_data[0].new_owner.to_string(),
        future_owner.public_key()
    );
    assert_eq!(transfer_data[0].subject_id, governance_id);

    let transfer_data = future_owner.get_pending_transfers().await.unwrap();
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

    let transfer_data = owner_governance.get_pending_transfers().await.unwrap();
    assert!(transfer_data.is_empty());

    let transfer_data = future_owner.get_pending_transfers().await.unwrap();
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

    let state = get_subject(node1, governance_id.clone(), None, true)
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
            policies_schema: BTreeMap::new(),
        },
    );
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
        } => {
            assert_eq!(payload, &governance_setup_payload);
            match evaluation_response {
                EvalResDB::Patch(_) => {}
                other => {
                    panic!("unexpected governance fact result: {other:?}")
                }
            }
            assert_eq!(*approval_success, Some(true));
        }
        other => panic!("unexpected governance fact event: {other:?}"),
    }

    match &api_events[2].event {
        RequestEventDB::GovernanceFact {
            payload,
            evaluation_response,
            approval_success,
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
// Prioridad: MEDIA.
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
// Prioridad: MEDIA.
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
