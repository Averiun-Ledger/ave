//! End-to-end tests of the level-3 compilation flow: compile quorum
//! and evidence, artifact staging/promotion/sweeps, corruption and
//! recovery, dead-pool behavior and the artifact fetch/serving protocol
//! (plan A compilers, plan B evaluators). All of it drives real
//! governance events through real nodes — the tests live apart from
//! `gov.rs` because that file pins governance flows (approvals, roles,
//! schema CRUD, viewpoints), not the compiler machinery.

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    str::FromStr,
    sync::atomic::Ordering,
    time::Duration,
};

use ave_common::{
    SchemaType,
    bridge::{
        request::ApprovalStateRes,
        response::{EvalResDB, RequestEventDB},
    },
    identity::{
        PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
    response::RequestState,
};
use ave_core::auth::AuthWitness;
use ave_core::config::CompilerNodeConfig;
use ave_core::governance::data::GovernanceData;
use ave_core::governance::model::{
    PolicyGov, Quorum, RoleGovIssuer, RolesGov, RolesTrackerSchemas,
};

use ave_network::{NodeType, RoutingNode};
use common::{
    CHANGED_SCHEMA_CONTRACT, CreateNodeConfig,
    CreateNodesAndConnectionsConfig, EXAMPLE_CONTRACT, EXAMPLE_CONTRACT_V2,
    FUEL_EXHAUSTING_CONTRACT, INVALID_EXAMPLE_CONTRACT, PORT_COUNTER,
    assert_governance_properties_eq, create_and_authorize_governance,
    create_node, create_nodes_and_connections, create_subject,
    emit_approve, emit_fact, get_abort_request, get_events, get_subject,
    governance_properties, node_running, try_create_node,
    wait_artifact_bytes, wait_artifact_bytes_eq, wait_request_state,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

#[test(tokio::test)]
// El contrato es invalido, se aborata la request
async fn test_invalid_contract() {
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
                    "contract": INVALID_EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
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
    assert_eq!(state.sn, 0);
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
// Sin quórum de compile la request entra en RebootTimeOut y sale sola
// cuando el compiler vuelve: con compilers {Owner, AveNode2} y Majority
// se exige el 2/2, así que el commit final prueba que AveNode2 compiló
// por red tras recuperarse. No hace falta reemitir nada — los reboots
// por TimeOut son ilimitados (el schedule repite su último valor).
async fn test_gov_compile_quorum_unmet_reboots_and_recovers() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // Segundo nodo: compiler y testigo de la gobernanza.
    let (mut node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído no hay quórum de compile: el fact con contrato
    // no puede commitear y la request entra en RebootTimeOut.
    let keys = node2.keys.clone();
    let local_db = node2_dirs[0].path().to_path_buf();
    let ext_db = node2_dirs[1].path().to_path_buf();

    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // AveNode2 vuelve con las mismas claves y bases de datos: la propia
    // request sale del reboot y commitea (quórum 2/2 con compile remoto
    // de AveNode2).
    let (node2, mut node2_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    dirs.append(&mut node2_dirs_new);
    node_running(&node2.api).await.unwrap();

    let state = get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Una request atascada en la fase compile (compiler caído, sin quórum)
// se puede abortar manualmente con limpieza: el manager para los hijos
// de la fase, registra el abort y la gobernanza no avanza.
async fn test_gov_compile_request_aborted_manually() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
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
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la request no puede cerrar el quórum de
    // compile: se queda peleando con la fase.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Abort manual con la fase compile en vuelo.
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
// Una request abortada a mitad de la fase compile nunca commitea: el
// abort barre su staging y reemitir el mismo cambio recompila y
// commitea con normalidad, sin colisiones con restos anteriores.
async fn test_gov_compile_abort_sweeps_staging_and_reemit_commits() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la request no puede cerrar el quórum de
    // compile: node1 compila a staging y se queda peleando con la fase.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    let request_id =
        emit_fact(&node1.api, governance_id.clone(), json.clone(), false)
            .await
            .unwrap();

    // Se espera a que el staging exista en disco (sondeo, como los
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 1);

    // Abort manual con la fase compile en vuelo: barre el staging.
    node1
        .api
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id,
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    // El abort barrió el staging: la request nunca va a commitear.
    assert!(staging_dirs().is_empty());

    // AveNode2 vuelve y la reemisión del mismo cambio commitea.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    // El staging se promovió: no queda nada temporal y el artefacto
    // oficial existe.
    assert!(staging_dirs().is_empty());
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .exists()
    );
}
#[test(tokio::test)]
// Un nodo que cae a mitad de la fase compile deja staging huérfano en
// disco: al reiniciar la request se reanuda sola, reutiliza o
// recompila ese staging y commitea cuando el quórum vuelve.
async fn test_gov_compile_orphan_staging_survives_restart() {
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la request no puede cerrar el quórum de
    // compile: node1 compila a staging y se queda peleando con la fase.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Se espera a que el staging exista en disco (sondeo, como los
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 1);

    // node1 cae a mitad de la fase compile: staging huérfano en disco.
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    // node1 reinicia con los mismos datos: la request se reanuda sola.
    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    // El staging huérfano sobrevive al reinicio: la request reanudada
    // lo reutiliza o lo recompila.
    assert_eq!(staging_dirs().len(), 1);

    // AveNode2 vuelve: el quórum de compile se cierra y commitea.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    // El staging se promovió: no queda nada temporal y el artefacto
    // oficial existe.
    assert!(staging_dirs().is_empty());
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .exists()
    );
}
#[test(tokio::test)]
// El staging de una fase compile ya completada también se barre si el
// owner aborta la request más tarde, en la fase de aprobación: la
// request nunca commitea y sus artefactos temporales no pueden quedar
// en disco.
async fn test_gov_compile_staging_swept_on_approval_abort() {
    let node1_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

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

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la aprobación no puede cerrar el quórum.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    // La compile y la evaluación sí completan: el staging queda
    // escrito y la fase de aprobación se queda en vuelo.
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

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    assert_eq!(staging_dirs().len(), 1);

    // Abort manual con la fase de aprobación en vuelo y el staging ya
    // escrito: el barrido también aplica.
    node1
        .api
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id,
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    assert!(staging_dirs().is_empty());

    // La gobernanza no ha avanzado: sigue en el SN 1.
    let state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}
#[test(tokio::test)]
// Un cambio de contrato que compila y evalúa bien pero se rechaza en
// aprobación commitea sin aplicar: su staging se barre y el contrato
// oficial sigue siendo el anterior, así que el sujeto sigue evaluando
// con el contrato numérico original.
async fn test_gov_compile_staging_swept_on_approval_reject() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = |dir: &tempfile::TempDir| -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: esquema con el contrato numérico, sus roles, y AveNode2 de
    // compiler y testigo. Con 2 compilers y quórum Majority la fase
    // compile exige el visto bueno de ambos: los dos stagean.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
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
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
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

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Sujeto del esquema: un evento numérico funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // SN 2: cambio a un contrato de strings. Compila y evalúa bien en
    // ambos compilers (los dos tienen staging), pero la aprobación lo
    // rechaza.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": CHANGED_SCHEMA_CONTRACT,
                    "new_initial_value": {
                        "data": "hola"
                    }
                }
            ]
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    assert_eq!(staging_dirs(&node1_contracts).len(), 1);
    assert_eq!(staging_dirs(&node2_contracts).len(), 1);

    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    // El evento commitea rechazado: el staging se barre y el contrato
    // no cambia.
    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert!(staging_dirs(&node1_contracts).is_empty());

    // El barrido es de todos los nodos que aplican el evento, no solo
    // del requester: AveNode2 aplica el evento al sincronizarse y su
    // staging también desaparece.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert!(staging_dirs(&node2_contracts).is_empty());

    // El contrato oficial sigue siendo el numérico: el evento de
    // números sigue funcionando.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 200 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
}
#[test(tokio::test)]
// Un cambio que solo toca el initial_value reutiliza el artefacto oficial
// (no hay contrato nuevo que compilar): si el nuevo valor no pasa el init
// check del contrato, el veredicto es un fallo determinista — recompilar
// el mismo source fallaría igual — y el evento commitea fallido sin tocar
// el esquema ni el artefacto.
async fn test_gov_compile_invalid_init_only_change_fails_event() {
    let node1_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: esquema con el contrato numérico y sus roles.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Sujeto del esquema: un evento numérico funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // SN 2 (fallido): cambio solo de initial_value, con un tipo que el
    // contrato no acepta (`one` es u32). La fase compile valida el nuevo
    // valor contra el artefacto oficial y vota el fallo.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_initial_value": {
                        "one": "abc",
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    // El evento commitea fallido: el sn avanza pero la versión y el
    // esquema no cambian.
    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 1);
    let schema = properties
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 0, "two": 0, "three": 0})
    );

    // Sin contrato nuevo no hay staging: nada que barrer y el artefacto
    // oficial sigue intacto.
    let staging: Vec<_> = fs::read_dir(node1_contracts.path())
        .unwrap()
        .filter_map(|entry| {
            let name =
                entry.unwrap().file_name().to_string_lossy().into_owned();
            name.contains("_temp_staging_").then_some(name)
        })
        .collect();
    assert!(staging.is_empty());
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .join("contract.cwasm")
            .exists()
    );

    // El artefacto oficial sigue sirviendo: el evento de números funciona.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 200 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
}
#[test(tokio::test)]
// Si el artefacto precompilado (contract.cwasm) está corrupto pero el
// wasm persiste íntegro, la primera evaluación tras rearrancar el nodo
// (sin el módulo cacheado en memoria) se autocura: precompila desde el
// wasm, vuelve a persistir el precompilado y el evento se evalúa con
// normalidad, sin pedir nada a la red.
async fn test_contract_cwasm_corruption_falls_back_to_wasm() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: esquema con el contrato numérico y sus roles.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Sujeto del esquema: un evento numérico funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // El módulo compilado queda cacheado en memoria tras el primer uso:
    // el fallback de disco solo se ejerce cuando el nodo arranca sin esa
    // caché. Se para el nodo, se corrompe el precompilado (el wasm, que
    // es la fuente de verdad del artefacto, no se toca) y se rearranca
    // con las mismas claves y bases de datos.
    let artifact_dir = node1_contracts
        .path()
        .join("contracts")
        .join(format!("{}_Example", governance_id));
    let cwasm_path = artifact_dir.join("contract.cwasm");
    assert!(cwasm_path.exists());

    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    fs::write(&cwasm_path, b"corrupted").unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    // La evaluación carga el contrato desde disco: el precompilado no
    // deserializa, se cae al wasm, se regenera el precompilado y el
    // evento se aplica con normalidad, sin pedir nada a la red.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 200 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    // Autocuración: el fallback vuelve a persistir el precompilado, así
    // que el fichero corrupto ha sido reemplazado.
    let healed = fs::read(&cwasm_path).unwrap();
    assert_ne!(healed, b"corrupted");
}
#[test(tokio::test)]
// Un alta de schema cuyo contrato compila pero cuyo initial_value no
// pasa el init check falla en la fase compile después de stagear: el
// evento commitea fallido y no queda residuo en disco — ni staging ni
// artefacto oficial.
async fn test_gov_compile_failed_add_leaves_no_artifacts() {
    let node1_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1 (fallido): el contrato compila pero `one` es u32 y llega un
    // string: el init check falla contra el artefacto stageado.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": "abc",
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    // El evento commitea fallido: el sn avanza pero la versión no y no
    // hay schemas.
    let state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 0);
    assert!(properties.schemas.is_empty());

    // Sin residuo en disco: el staging se barre al commitear fallido y
    // no se crea artefacto oficial.
    let staging: Vec<_> = fs::read_dir(node1_contracts.path())
        .unwrap()
        .filter_map(|entry| {
            let name =
                entry.unwrap().file_name().to_string_lossy().into_owned();
            name.contains("_temp_staging_").then_some(name)
        })
        .collect();
    assert!(staging.is_empty());
    assert!(
        !node1_contracts
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .exists()
    );
}
#[test(tokio::test)]
// Si los dos ficheros del artefacto (wasm y precompilado) están corruptos
// no hay fallback local posible: la primera evaluación tras rearrancar el
// nodo detecta el hash mismatch y recompila desde el source del schema,
// regenerando los artefactos, y el evento se aplica con normalidad.
async fn test_contract_full_artifact_corruption_recompiles_on_boot() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: esquema con el contrato numérico y sus roles.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Sujeto del esquema: un evento numérico funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // Corrupción total con el nodo parado (sin la caché en memoria): ni
    // el precompilado ni el wasm sobreviven íntegros.
    let artifact_dir = node1_contracts
        .path()
        .join("contracts")
        .join(format!("{}_Example", governance_id));
    let wasm_path = artifact_dir.join("contract.wasm");
    let cwasm_path = artifact_dir.join("contract.cwasm");
    assert!(wasm_path.exists());
    assert!(cwasm_path.exists());

    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    fs::write(&wasm_path, b"corrupted").unwrap();
    fs::write(&cwasm_path, b"corrupted").unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    // La evaluación carga el contrato desde disco: ambos artefactos
    // fallan su hash, se recompila desde el source y el evento se aplica
    // con normalidad.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 200 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    // La recompilación vuelve a persistir los artefactos: los ficheros
    // corruptos han sido reemplazados.
    let healed_wasm = fs::read(&wasm_path).unwrap();
    assert_ne!(healed_wasm, b"corrupted");
    let healed_cwasm = fs::read(&cwasm_path).unwrap();
    assert_ne!(healed_cwasm, b"corrupted");
}
#[test(tokio::test)]
// Un fallo de disco al promover el staging a oficial durante el commit
// es un fallo local fatal: el nodo cae controlado en vez de quedarse
// reintentando para siempre.
async fn test_gov_compile_promotion_disk_failure_is_fatal() {
    use std::os::unix::fs::PermissionsExt;

    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: esquema con contrato y AveNode2 de compiler y testigo.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
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
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la request se queda peleando con la fase
    // compile tras escribir el staging.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Se espera a que el staging exista en disco (sondeo, como los
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 1);

    // Disco roto en caliente: el directorio de contratos queda sin
    // permisos de escritura, así que el rename de la promoción fallará.
    fs::set_permissions(
        node1_contracts.path(),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();

    // AveNode2 vuelve: el quórum se cierra y el commit intenta la
    // promoción con el disco roto.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    // Un nodo que no puede hacer su trabajo es un nodo muerto: el fallo
    // de disco en la promoción tumba el nodo entero de forma controlada.
    join_all(node1.handler.iter_mut()).await;

    // Restaurar permisos para que el TempDir pueda limpiarse al salir.
    fs::set_permissions(
        node1_contracts.path(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}
#[test(tokio::test)]
// Un staging corrompido en disco entre la compile y el commit (bitrot,
// escritura parcial) no rompe al nodo: el evento commitea y en la
// siguiente evaluación la lectura detecta el mismatch de hash y
// recompila, autorrecuperándose.
async fn test_gov_compile_staging_corruption_self_heals() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la request se queda peleando con la fase
    // compile tras escribir el staging.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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

    emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Se espera a que el staging exista en disco (sondeo, como los
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let staging = staging_dirs();
    assert_eq!(staging.len(), 1);

    // El wasm staged se corrompe antes de que el evento commitee.
    fs::write(
        node1_contracts
            .path()
            .join(&staging[0])
            .join("contract.wasm"),
        b"corrupted",
    )
    .unwrap();

    // AveNode2 vuelve: el quórum se cierra y el evento commitea con el
    // artefacto corrompido promovido.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert!(staging_dirs().is_empty());

    // La primera evaluación lee el artefacto oficial corrompido,
    // detecta el mismatch de hash y recompila: el nodo se
    // autorrecupera y el sujeto funciona.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({ "ModOne": { "data": 100 } }),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}
#[test(tokio::test)]
// Un evento que añade dos schemas con contratos distintos genera dos
// stagings: si la request se aborta, el barrido los elimina todos.
async fn test_gov_compile_abort_sweeps_every_staging() {
    let node1_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(node1_contracts.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1: AveNode2 pasa a ser compiler y testigo. Con 2 compilers y
    // quórum Majority la fase compile exige el visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Con AveNode2 caído la request se queda peleando con la fase
    // compile tras escribir los stagings.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

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
                },
                {
                    "id": "ExampleV2",
                    "contract": EXAMPLE_CONTRACT_V2,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Se espera a que ambos stagings existan en disco (sondeo, como
    // los helpers).
    for _ in 0..100 {
        if staging_dirs().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 2);

    // Abort manual con la fase compile en vuelo: barre los dos
    // stagings.
    node1
        .api
        .manual_request_abort(governance_id.clone())
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id,
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    assert!(staging_dirs().is_empty());

    // La gobernanza no ha avanzado: sigue en el SN 1.
    let state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
}
#[test(tokio::test)]
// El artefacto compilado en la fase compile queda en staging hasta que
// el evento commitea: si el commit es exitoso se promueve al slot
// oficial y el staging desaparece (sin recompilar); si el evento
// commitea fallido, el staging se borra y el artefacto nunca se vuelve
// oficial.
async fn test_gov_compile_staging_promoted_and_swept() {
    let contracts_dir = tempfile::tempdir().unwrap();
    let (node, _dirs) = create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    let temp_staging_dirs = || -> Vec<String> {
        let prefix = format!("{}_temp_staging_", governance_id);
        fs::read_dir(contracts_dir.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(&prefix).then_some(name)
            })
            .collect()
    };

    // SN 1 (exitoso): se añade un schema con contrato. La fase compile
    // deja el artefacto en staging y, al commitear, se promueve al slot
    // oficial: el staging desaparece.
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

    emit_fact(&node.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&node.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert!(
        contracts_dir
            .path()
            .join("contracts")
            .join(format!("{}_Example", governance_id))
            .exists(),
        "el artefacto promovido debe existir en el slot oficial"
    );
    assert!(
        temp_staging_dirs().is_empty(),
        "tras el commit exitoso no debe quedar staging: {:?}",
        temp_staging_dirs()
    );

    // SN 2 (fallido): se añade otro schema con contrato (se compila y
    // queda en staging) pero el evento también da el rol compiler a un
    // miembro que no existe, así que la evaluación lo rechaza. El
    // evento commitea fallido: el staging se borra y el artefacto de
    // Example2 nunca llega al slot oficial.
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
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "compiler": ["NotAMember"]
                }
            }
        }
    });

    emit_fact(&node.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    let state = get_subject(&node.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 1);
    assert_eq!(properties.schemas.len(), 1);

    assert!(
        temp_staging_dirs().is_empty(),
        "tras el commit fallido no debe quedar staging: {:?}",
        temp_staging_dirs()
    );
    assert!(
        !contracts_dir
            .path()
            .join("contracts")
            .join(format!("{}_Example2", governance_id))
            .exists(),
        "el artefacto de un evento fallido no debe ser oficial"
    );
}
#[test(tokio::test)]
// Un compilador con el pool caído responde `Unavailable` y no arrastra
// la request: el quorum de compilación (Majority de 3 = 2) se cierra con
// el resto de compiladores y el fact de gobernanza con contrato se
// confirma.
async fn test_gov_compiler_unavailable_quorum_holds() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    // Tercer nodo cuyo compilador apunta a un endpoint muerto: toda
    // compilación falla con `CompilersUnavailable`.
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", port),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node3_dirs);
    node_running(&node3.api).await.unwrap();
    let node3 = &node3.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2, node3]).await;

    // SN 1: los tres nodos pasan a ser evaluadores, witnesses y
    // compiladores de la gobernanza. Este fact no añade contratos, así
    // que no necesita compilación y lo evalúa el Owner (quorum Majority
    // de 1 evaluador y 1 compilador).
    let json = json!({
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
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"],
                    "evaluator": ["AveNode2", "AveNode3"],
                    "compiler": ["AveNode2", "AveNode3"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Esperar a que el fact commitee en node1 antes de sincronizar:
    // wait_request puede terminar en Approval, antes del commit real.
    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Los evaluadores deben tener la gobernanza en SN 1 antes del siguiente
    // fact, o responderían por desincronización de versión.
    node2.update_subject(governance_id.clone()).await.unwrap();
    node3.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    get_subject(node3, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: fact que añade un schema con contrato. La fase de compilación
    // exige quorum Majority de 3 compiladores (2): node3 no puede compilar
    // y responde `Unavailable`, pero el quorum se cierra con node1 y
    // node2. La evaluación posterior es nativa y no toca el pool.
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.sn, 2);
    assert!(state.active);

    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
    assert_eq!(gov.members.len(), 3);
}
#[test(tokio::test)]
// Si el quorum de compilación es inalcanzable porque un compilador no
// está disponible, la request no se pierde ni se marca inválida: entra en
// RebootTimeOut y el nodo emisor sigue operativo.
async fn test_gov_compiler_unavailable_quorum_fails_reboot() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // Segundo nodo con el compilador apuntando a un endpoint muerto.
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", port),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();
    let node2 = &node2.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: node2 pasa a ser evaluador, witness y compilador. Con 2
    // compiladores y quorum Majority la fase de compilación exige el
    // visto bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "evaluator": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Esperar a que el fact commitee en node1 antes de sincronizar:
    // wait_request puede terminar en Approval, antes del commit real.
    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Fact con contrato: node1 compila correctamente pero node2 responde
    // `Unavailable` (pool muerto); sin quorum de compilación la request
    // entra en RebootTimeOut.
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

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // La gobernanza no avanza y el nodo emisor sigue respondiendo.
    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert_eq!(state.sn, 1);
    assert!(state.active);
}
#[test(tokio::test)]
// Un contrato que agota el fuel es un fallo determinista del contrato:
// todos los evaluadores votan Error idéntico, el evento queda registrado
// como fallido y ningún nodo se tumba (antes cada evaluador crasheaba —
// DoS por contrato).
async fn test_contract_fuel_exhaustion_fails_event_nodes_survive() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: schema con un contrato que entra en bucle en ModOne. Ambos
    // nodos son testigos de la gobernanza y evaluadores del schema, así
    // los dos ejecutan el contrato y votan.
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
                    "id": "Fuel",
                    "contract": FUEL_EXHAUSTING_CONTRACT,
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
                    "witness": ["AveNode2"]
                }
            },
            "schema": [
                {
                    "schema_id": "Fuel",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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

    // Esperar el commit en node1 y sincronizar node2 antes de seguir.
    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // La creación del subject funciona: init_check no ejecuta el bucle.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Fuel", "", true)
            .await
            .unwrap();

    // node2 es testigo del schema desde antes de la creación: recibe el
    // evento Create por distribución automática.
    get_subject(node2, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    // ModOne entra en bucle: ambos evaluadores agotan el fuel y votan
    // Error idéntico, así que el agregador cierra Error (no Diff-reboot)
    // y el evento queda registrado como fallido.
    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // El evento fallido avanza el sn pero no modifica las propiedades.
    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 0}));

    // El evento registrado lleva el error de evaluación (fuel agotado).
    let events = get_events(node1, subject_id.clone(), 2, true)
        .await
        .unwrap();
    match &events[1].event {
        RequestEventDB::TrackerFactFull {
            evaluation_response,
            ..
        } => match evaluation_response {
            EvalResDB::Error(error) => assert!(!error.is_empty()),
            other => panic!("unexpected evaluation result: {other:?}"),
        },
        other => panic!("unexpected event: {other:?}"),
    }

    // node2 también lo recibe: los dos nodos siguen vivos y consistentes.
    get_subject(node2, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Y el nodo sigue operando con normalidad: un fact posterior de
    // gobernanza completa sin problema.
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
}
#[test(tokio::test)]
// Un fallo de disco al persistir los artefactos de un contrato es un
// fallo local fatal, no un problema del pool de compiladores: el nodo no
// puede evaluar ese schema de forma fiable y el arranque debe fallar de
// forma controlada en lugar de continuar en modo degradado.
async fn test_gov_contract_artifacts_disk_failure_node_fails_boot() {
    use std::os::unix::fs::PermissionsExt;

    let contracts_dir = tempfile::tempdir().unwrap();
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, dirs) = create_node(CreateNodeConfig {
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    // SN 1: schema con contrato. La compilación final persiste los
    // artefactos bajo el directorio de contratos del nodo.
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
    emit_fact(&node.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&node.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert!(contracts_dir.path().join("contracts").exists());

    // Apagado ordenado conservando claves y bases de datos.
    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    // Simular corrupción de disco: los artefactos desaparecen y el
    // directorio queda sin permisos de escritura, así la recompilación
    // del arranque no puede persistir el artefacto.
    fs::remove_dir_all(contracts_dir.path().join("contracts")).unwrap();
    fs::set_permissions(
        contracts_dir.path(),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();

    let result = try_create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    // Restaurar permisos para que el TempDir pueda limpiarse al salir.
    fs::set_permissions(
        contracts_dir.path(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    match result {
        Err(ave_core::error::Error::ActorCreation { actor, .. }) => {
            assert_eq!(actor, "node");
        }
        Err(error) => panic!("unexpected boot error: {error}"),
        Ok(_) => {
            panic!("node booted with a read-only contracts directory")
        }
    }
}
#[test(tokio::test)]
// Un compilador cuya clave pública no coincide con el pin configurado es
// indistinguible de uno comprometido: el cliente descarta sus respuestas
// (firma de atestación inválida), el nodo responde `Unavailable` en la
// fase de compilación sin emitir veredicto y, al no cerrarse el quorum,
// la request entra en RebootTimeOut en lugar de perderse. Ambos nodos
// siguen operativos.
async fn test_gov_compiler_wrong_pin_unavailable_reboot() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // Segundo nodo apuntando al compilador embebido real pero con un pin
    // de clave pública incorrecto: toda respuesta se descarta.
    let mut compiler_config =
        ave_core::test_compiler::test_compiler_config().await;
    compiler_config.compiler_public_key = Some(
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string(),
    );

    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(compiler_config),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();
    let node2 = &node2.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: node2 pasa a ser evaluador, testigo y compilador. Con 2
    // compiladores y quorum Majority la compilación exige el visto
    // bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "evaluator": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Esperar a que el fact commitee en node1 antes de sincronizar:
    // wait_request puede terminar en Approval, antes del commit real.
    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Fact con contrato: node1 compila correctamente pero las respuestas
    // del compilador de node2 se descartan por el pin; sin quorum de
    // compilación la request entra en RebootTimeOut.
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

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // La gobernanza no avanza y ambos nodos siguen respondiendo.
    let state = get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert_eq!(state.sn, 1);
    assert!(state.active);
    node_running(node2).await.unwrap();
}
#[test(tokio::test)]
// La compilación con el pool caído degrada la evaluación sin tumbar el
// nodo: mientras node3 no dispone del artefacto responde `Unavailable`,
// el quorum se cierra con el resto de evaluadores y el nodo sigue
// aplicando el ledger como testigo. Tras commitear el evento, node3
// intenta reponer el artefacto por fetch desde los compiladores de la
// red, así que la degradación puede ser transitoria.
async fn test_gov_evaluator_degraded_compile_survives_and_serves_ledger() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    // Tercer nodo cuyo compilador apunta a un endpoint muerto.
    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node3_dirs);
    node_running(&node3.api).await.unwrap();
    let node3 = &node3.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2, node3]).await;

    // SN 1: los tres nodos pasan a ser evaluadores y testigos de la
    // gobernanza. Sin contratos de por medio, la evalúa el Owner.
    let json = json!({
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
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"],
                    "evaluator": ["AveNode2", "AveNode3"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    node3.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    get_subject(node3, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: schema con contrato y roles de schema. La evaluación temporal
    // de node3 responde `Unavailable` pero el quorum Majority (2 de 3) se
    // cierra con node1 y node2. Al commitear, node3 no puede compilar
    // (pool muerto) y arranca el fetch del artefacto desde un compilador
    // de la red; hasta que el fetch termina sigue sin artefacto local.
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
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    node3.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    get_subject(node3, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Creación del subject: si node3 aún no ha terminado el fetch
    // responde `Unavailable` (contrato no encontrado) y el quorum se
    // cierra con node1 y node2; si ya lo tiene, evalúa con normalidad.
    // En ambos casos el evento commitea.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(node2, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    get_subject(node3, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    // El fact commitea con independencia de si node3 ya recuperó el
    // artefacto por fetch (quorum Majority: basta 2 de 3 evaluadores).
    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    // El nodo sigue vivo y aplica el ledger como testigo.
    let state = get_subject(node3, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));
}
#[test(tokio::test)]
// Un evaluador con el pool muerto no queda bloqueado tras un cambio de
// contrato: al commitear el evento registra el ancla de compilación de
// la nueva versión y repone el artefacto por fetch desde los
// compiladores de la red (verificado contra el ancla), volviendo a
// evaluar con el quorum completo.
async fn test_evaluator_with_dead_pool_fetches_contract_and_evaluates() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // node2 con un directorio de contratos explícito: el artefacto v1
    // debe sobrevivir al reinicio para que el arranque lo cargue de
    // disco (si no se preserva, el restart genera un directorio vacío y
    // el escenario cambia: el nodo arrancaría ya sin artefacto).
    let contracts_dir = tempfile::tempdir().unwrap();
    let (mut node2_data, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2_data.api).await.unwrap();

    let node2 = &node2_data.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: miembro + schema "Example" (v1). node2 es testigo de la
    // gobernanza (no evaluador: los facts de gobernanza commitean solo
    // con el Owner) y evaluador del schema; el quorum Majority de
    // evaluación del schema exige a los dos evaluadores.
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
                    "witness": ["AveNode2"]
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
                            },
                            {
                                "name": "AveNode2",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Subject y fact con la v1: ambos evaluadores operativos.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(node2, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Esperar a que node2 aplique el evento antes de apagarlo: reiniciar
    // un nodo desincronizado degrada todo lo posterior bajo estrés.
    get_subject(node2, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Reinicio de node2 con el compilador muerto conservando el
    // directorio de contratos: el artefacto v1 está en disco, así que el
    // arranque no necesita al pool.
    let keys = node2_data.keys.clone();
    let local_db = node2_dirs[0].path().to_path_buf();
    let ext_db = node2_dirs[1].path().to_path_buf();

    node2_data.token.cancel();
    join_all(node2_data.handler.iter_mut()).await;

    let (node2, mut node2_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    dirs.append(&mut node2_dirs_new);
    node_running(&node2.api).await.unwrap();
    let node2 = &node2.api;

    // SN 2: cambio de contrato a la v2 (ModThree=50 pasa a ser válido).
    // Lo evalúa el Owner únicamente. Al commitear, node2 registra el
    // ancla de compilación de la v2 y, como no puede recompilar (pool
    // muerto), arranca el fetch del artefacto desde node1.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Sincronizar node2: al aplicar SN 2 arranca el fetch de la v2.
    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // ModThree=50 solo es válido con la v2 y el quorum Majority con 2
    // evaluadores exige el visto bueno de ambos. Si node2 aún no ha
    // terminado el fetch responde `Unavailable` y la request reintenta
    // hasta que dispone del artefacto: el evento solo commitea cuando
    // node2 evalúa con la v2 verificada contra el ancla.
    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 0, "three": 50}));

    // node2 commiteó el evento: evaluó con la v2 obtenida por fetch.
    let state = get_subject(node2, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 0, "three": 50}));

    // El artefacto fetcheado quedó persistido en el directorio de
    // contratos preservado de node2.
    assert!(
        contracts_dir
            .path()
            .join("contracts")
            .join(format!("{governance_id}_Example"))
            .exists()
    );

    // El evaluador recuperado sigue operativo.
    node_running(node2).await.unwrap();
}
#[test(tokio::test)]
// Un fallo local fatal durante la compilación pre-commit de un contrato
// (el disco no puede persistir el staging) no se degrada: el nodo se
// baja controladamente, el evento no commitea y, con el disco aún roto,
// el reinicio se niega a arrancar en modo degradado.
async fn test_gov_contract_refresh_disk_failure_restart_is_fatal() {
    use std::os::unix::fs::PermissionsExt;

    let contracts_dir = tempfile::tempdir().unwrap();
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, dirs) = create_node(CreateNodeConfig {
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    // SN 1: schema "Example" con la v1 del contrato.
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
    emit_fact(&node.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&node.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert!(contracts_dir.path().join("contracts").exists());

    // Disco roto en caliente: los artefactos desaparecen y el directorio
    // queda sin permisos de escritura.
    fs::remove_dir_all(contracts_dir.path().join("contracts")).unwrap();
    fs::set_permissions(
        contracts_dir.path(),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();

    // SN 2: cambio de contrato a la v2. La compilación es pre-commit: el
    // worker intenta crear el staging con el disco roto, un fallo local
    // fatal. Se emite async porque el nodo entero se baja justo después.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ]
        }
    });
    emit_fact(&node.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Un nodo que no puede hacer su trabajo es un nodo muerto: el fallo
    // de disco tumba el nodo entero (no solo la gobernanza) y el evento
    // no llega a commitear.
    join_all(node.handler.iter_mut()).await;

    // Con el disco aún roto el nodo no debe arrancar degradado: el fallo
    // local fatal vuelve a aparecer al recuperar los artefactos en el
    // arranque.
    let result = try_create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(node.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    // Restaurar permisos para que el TempDir pueda limpiarse al salir.
    fs::set_permissions(
        contracts_dir.path(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    match result {
        Err(ave_core::error::Error::ActorCreation { actor, .. }) => {
            assert_eq!(actor, "node");
        }
        Err(error) => panic!("unexpected boot error: {error}"),
        Ok(_) => {
            panic!("node booted degraded with a read-only contracts directory")
        }
    }
}
#[test(tokio::test)]
// Un compilador degradado se recupera al reiniciar con un pool sano:
// vuelve a compilar en la fase de compilación y la request sale del
// reboot. El quorum Majority exige a los dos compiladores, así que el
// commit del fact prueba que el nodo recuperado participa de nuevo.
async fn test_gov_compiler_recovers_after_pool_restart() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // Segundo nodo con el compilador apuntando a un endpoint muerto.
    let (mut node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: node2 pasa a ser evaluador, testigo y compilador. Con 2
    // compiladores y quorum Majority la compilación exige el visto
    // bueno de ambos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "evaluator": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Intento de fact con contrato: node2 no puede compilar (pool
    // muerto), el quorum de compilación no se cierra y la request entra
    // en RebootTimeOut.
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

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // Reinicio con el pool sano (el embebido autoinyectado): node2
    // vuelve a compilar en la fase de compilación.
    let keys = node2.keys.clone();
    let local_db = node2_dirs[0].path().to_path_buf();
    let ext_db = node2_dirs[1].path().to_path_buf();

    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, mut node2_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    dirs.append(&mut node2_dirs_new);
    node_running(&node2.api).await.unwrap();

    // Con el pool recuperado, la propia request sale del reboot y
    // commitea: como el quorum de compilación exige el voto de node2, el
    // commit prueba la recuperación. No hace falta reemitir nada — los
    // reboots por TimeOut son ilimitados (el schedule repite su último
    // valor).
    let state = get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Un artefacto corrupto en disco no es un fallo fatal: el check de
// integridad (hash del wasm y del precompilado) lo detecta en el
// arranque, lo descarta y recompila desde el pool. El nodo arranca y
// evalúa con normalidad.
async fn test_contract_artifact_corruption_self_heals_on_boot() {
    let contracts_dir = tempfile::tempdir().unwrap();
    let (mut node, dirs) = create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    // SN 1: schema con contrato y roles del Owner; la compilación final
    // persiste los artefactos en el directorio de contratos.
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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

    emit_fact(&node.api, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&node.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert!(contracts_dir.path().join("contracts").exists());

    // Apagado ordenado conservando claves y bases de datos.
    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    // Corromper todos los artefactos persistidos: los hashes no
    // coincidirán con los registrados y el loader los descartará.
    let contracts_root = contracts_dir.path().join("contracts");
    for entry in fs::read_dir(&contracts_root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            for artifact in fs::read_dir(entry.path()).unwrap() {
                let artifact = artifact.unwrap();
                if artifact.file_type().unwrap().is_file() {
                    fs::write(artifact.path(), b"corrupted artifact").unwrap();
                }
            }
        }
    }

    // Reinicio: el loader detecta el hash mismatch, recompila desde el
    // pool y el nodo arranca con normalidad.
    let (node, _new_dirs) = create_node(CreateNodeConfig {
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    // El nodo evalúa con el artefacto recompilado: subject + fact.
    let (subject_id, ..) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));
}
#[test(tokio::test)]
// La degradación es por schema, no por nodo: un evaluador que reinicia
// con el pool caído pero con el artefacto en disco sigue evaluando ese
// schema con total normalidad (solo queda mudo para schemas que no puede
// obtener). El quorum Majority exige a los dos evaluadores, así que el
// commit prueba que node2 votó con el artefacto cacheado.
async fn test_contract_cached_artifact_evaluates_with_dead_compiler_pool() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // node2 con un directorio de contratos explícito: el artefacto debe
    // sobrevivir al reinicio para que el arranque lo cargue de disco (si
    // no se preserva, el restart genera un directorio vacío y el nodo
    // degradaría, que no es lo que se quiere probar).
    let contracts_dir = tempfile::tempdir().unwrap();
    let (mut node2_data, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2_data.api).await.unwrap();

    let node2 = &node2_data.api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // SN 1: miembro + schema "Example". node2 es testigo de la
    // gobernanza y evaluador del schema; el quorum Majority exige a los
    // dos evaluadores.
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
                    "witness": ["AveNode2"]
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
                            },
                            {
                                "name": "AveNode2",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Subject y fact con ambos nodos sanos: el artefacto queda
    // persistido en disco en node2.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(node2, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Esperar a que node2 aplique el evento antes de apagarlo: reiniciar
    // un nodo desincronizado degrada todo lo posterior bajo estrés.
    get_subject(node2, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Reinicio de node2 con el compilador muerto conservando el
    // directorio de contratos: el arranque carga el artefacto desde
    // disco y no necesita al pool.
    let keys = node2_data.keys.clone();
    let local_db = node2_dirs[0].path().to_path_buf();
    let ext_db = node2_dirs[1].path().to_path_buf();

    node2_data.token.cancel();
    join_all(node2_data.handler.iter_mut()).await;

    let (node2, mut node2_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    dirs.append(&mut node2_dirs_new);
    node_running(&node2.api).await.unwrap();
    let node2 = &node2.api;

    // Fact posterior: node2 evalúa con el artefacto cacheado y el fact
    // commitea. Sin su voto no habría quorum, así que el commit prueba
    // que el nodo sigue operativo para este schema pese al pool caído.
    // Se emite async y se espera el commit con get_subject (acotado):
    // wait_request no tiene límite y bajo estrés la request puede pasar
    // por varias rondas de reboot antes de commitear.
    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModTwo": {"data": 9}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert_eq!(state.properties, json!({"one": 1, "two": 9, "three": 0}));

    let state = get_subject(node2, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert_eq!(state.properties, json!({"one": 1, "two": 9, "three": 0}));
}
#[test(tokio::test)]
// Un evaluador de gobernanza SIN rol compiler y con el pool muerto evalúa
// y vota eventos de gobernanza (incluido un alta de schema que compilan
// OTROS nodos): la evaluación de gobernanza es código nativo y nunca toca
// el pool. El quorum Majority con 2 evaluadores exige ambos votos, así que
// el commit prueba que AveNode2 evaluó con el pool caído.
async fn test_gov_evaluator_dead_pool_votes_schema_add() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    // AveNode2: evaluador y testigo de gobernanza con el pool muerto.
    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 pasa a ser evaluador y testigo de la gobernanza.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "evaluator": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: alta del schema con contrato. Lo compila el Owner (único
    // compiler); la evaluación de gobernanza exige el voto de AveNode2,
    // que evalúa nativamente con su pool muerto.
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let state = get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Un cambio de schema que solo toca viewpoints (sin contrato ni
// initial_value) no pasa por la fase de compilación: con el pool muerto
// tras el reinicio el evento commitea igualmente y el schema sigue
// evaluando con el artefacto persistido.
async fn test_gov_viewpoints_only_change_no_compile_dead_pool() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (mut node1, mut node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: schema "Example" con viewpoints iniciales y sus roles.
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
                    "viewpoints": ["base"]
                }
            ]
        },
        "roles": {
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Reinicio con el pool muerto conservando claves, bases de datos y el
    // directorio de contratos (el artefacto v1 carga de disco).
    let keys = node1.keys.clone();
    let local_db = node1_dirs[0].path().to_path_buf();
    let ext_db = node1_dirs[1].path().to_path_buf();

    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    let (node1, mut node1_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    node1_dirs.append(&mut node1_dirs_new);
    node_running(&node1.api).await.unwrap();

    // SN 2: cambio solo de viewpoints. Nada que compilar: el evento
    // commitea con el pool muerto.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_viewpoints": ["agua"]
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    let schema = gov
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.viewpoints, BTreeSet::from(["agua".to_owned()]));

    // El schema sigue evaluando con el artefacto persistido.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node1.api).await.unwrap();
}
#[test(tokio::test)]
// Un cambio solo de initial_value con el pool muerto y el artefacto
// oficial sano reutiliza los bytes persistidos: la fase de compilación
// revalida el nuevo init contra el artefacto en disco, el evento commitea
// sin ninguna build (el pool muerto lo prueba: cualquier llamada al pool
// impediría el commit) y el ancla no se mueve (mismo wasm tras el commit).
async fn test_gov_init_only_change_reuses_artifact_dead_pool() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (mut node1, mut node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: schema "Example" con la v1 del contrato.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let wasm_path = contracts_dir
        .path()
        .join("contracts")
        .join(format!("{governance_id}_Example"))
        .join("contract.wasm");
    let wasm_before = fs::read(&wasm_path).unwrap();

    // Reinicio con el pool muerto conservando claves, bases de datos y el
    // directorio de contratos.
    let keys = node1.keys.clone();
    let local_db = node1_dirs[0].path().to_path_buf();
    let ext_db = node1_dirs[1].path().to_path_buf();

    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    let (node1, mut node1_dirs_new) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    node1_dirs.append(&mut node1_dirs_new);
    node_running(&node1.api).await.unwrap();

    // SN 2: cambio solo de initial_value. El worker revalida el nuevo
    // valor contra el artefacto persistido y commitea sin tocar el pool.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_initial_value": {
                        "one": 1,
                        "two": 2,
                        "three": 3
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert_eq!(gov.version, 2);
    let schema = gov
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 1, "two": 2, "three": 3})
    );

    // El ancla no se movió: el wasm oficial es byte a byte el mismo.
    let wasm_after = fs::read(&wasm_path).unwrap();
    assert_eq!(wasm_before, wasm_after);

    node_running(&node1.api).await.unwrap();
}
#[test(tokio::test)]
// Un mismo evento que da de alta dos schemas con la MISMA fuente de
// contrato promueve ambos artefactos (staging nombrado por schema) y
// ambos schemas evalúan con normalidad.
async fn test_gov_compile_same_source_two_schemas() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: dos schemas con la misma fuente de contrato en un evento.
    let schema_roles = |schema_id: &str| {
        json!({
            "schema_id": schema_id,
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
                        "quantity": 10
                    }
                ],
                "issuer": [
                    {
                        "name": "Owner",
                        "namespace": []
                    }
                ]
            }
        })
    };

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "ExampleA",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "ExampleB",
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
            "schema": [
                schema_roles("ExampleA"),
                schema_roles("ExampleB")
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("ExampleA".to_owned()))
    );
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("ExampleB".to_owned()))
    );

    // Ambos artefactos quedaron promovidos.
    for schema_id in ["ExampleA", "ExampleB"] {
        assert!(
            contracts_dir
                .path()
                .join("contracts")
                .join(format!("{governance_id}_{schema_id}"))
                .join("contract.cwasm")
                .exists()
        );
    }

    // Y ambos schemas evalúan.
    for (schema_id, value) in [("ExampleA", 1), ("ExampleB", 2)] {
        let (subject_id, ..) = create_subject(
            &node1.api,
            governance_id.clone(),
            schema_id,
            "",
            true,
        )
        .await
        .unwrap();

        emit_fact(
            &node1.api,
            subject_id.clone(),
            json!({"ModOne": {"data": value}}),
            true,
        )
        .await
        .unwrap();

        let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
            .await
            .unwrap();
        assert_eq!(
            state.properties,
            json!({"one": value, "two": 0, "three": 0})
        );
    }

    node_running(&node1.api).await.unwrap();
}
#[test(tokio::test)]
// Un cambio solo de initial_value con el artefacto oficial borrado del
// disco fuerza una recompilación verificada contra el ancla del ledger:
// la build reproduce los bytes anclados, la ronda cierra Ok y el ancla no
// se mueve (el wasm repuesto es byte a byte el original).
async fn test_gov_init_only_change_missing_artifact_recompiles_anchored() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: schema "Example" con la v1 del contrato.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_dir = contracts_dir
        .path()
        .join("contracts")
        .join(format!("{governance_id}_Example"));
    let wasm_before = fs::read(artifact_dir.join("contract.wasm")).unwrap();

    // El artefacto oficial desaparece del disco en caliente.
    fs::remove_dir_all(&artifact_dir).unwrap();

    // SN 2: cambio solo de initial_value. El worker no encuentra el
    // artefacto, recompila desde el pool y la verificación contra el
    // ancla pasa: la build es determinista y reproduce los bytes
    // anclados.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_initial_value": {
                        "one": 5,
                        "two": 6,
                        "three": 7
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert_eq!(gov.version, 2);
    let schema = gov
        .schemas
        .get(&SchemaType::Type("Example".to_owned()))
        .expect("el schema Example debe existir");
    assert_eq!(schema.contract, EXAMPLE_CONTRACT);
    assert_eq!(
        schema.initial_value.0,
        json!({"one": 5, "two": 6, "three": 7})
    );

    // El ancla no se movió: el artefacto repuesto reproduce los bytes
    // originales.
    let wasm_after = fs::read(artifact_dir.join("contract.wasm")).unwrap();
    assert_eq!(wasm_before, wasm_after);

    node_running(&node1.api).await.unwrap();
}
#[test(tokio::test)]
// Al commitear un cambio de contrato TODOS los nodos que aplican el
// evento registran el ancla, incluidos testigos sin rol de evaluador ni
// compilador: el testigo pasa a evaluador DESPUÉS del commit y su fetch
// se verifica contra el ancla que registró cuando era solo testigo.
async fn test_anchor_recorded_on_witness_without_roles() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let node2_contracts = tempfile::tempdir().unwrap();
    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 es solo testigo de la gobernanza. El schema v1 se
    // crea con roles del Owner únicamente.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: cambio de contrato a la v2. AveNode2 lo aplica como simple
    // testigo y registra el ancla de la v2.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: AveNode2 pasa a ser evaluador del schema. Al aplicar el
    // evento necesita el artefacto v2: lo pide a la red y lo verifica
    // contra el ancla que registró cuando era testigo.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // El fetch verificado contra el ancla termina: el artefacto v2 está
    // en disco en AveNode2.
    let artifact_name = format!("{governance_id}_Example");
    let node2_v2 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert!(!node2_v2.is_empty());

    // Un fact solo válido con la v2 (ModThree=50) commitea con el quorum
    // de 2 evaluadores: prueba que AveNode2 evalúa con la v2.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    let state = get_subject(&node2.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// El ancla sobrevive a perder y recuperar el rol de evaluador sin eventos
// intermedios: si el artefacto local desapareció, la recuperación del rol
// relanza el fetch verificado contra el ancla conservada.
async fn test_fetch_anchor_survives_role_loss_and_regain() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let node1_contracts = tempfile::tempdir().unwrap();
    let _keep_node1_contracts = &node1_contracts;

    let node2_contracts = tempfile::tempdir().unwrap();
    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // SN 1: AveNode2 evaluador y testigo del schema v1.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
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
                            },
                            {
                                "name": "AveNode2",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // AveNode2 dispone del artefacto v1 (fetcheado del Owner).
    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: AveNode2 pierde el rol de evaluador. El ancla se conserva.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El artefacto local desaparece del disco (el ancla sigue en el
    // registro).
    fs::remove_dir_all(
        node2_contracts.path().join("contracts").join(&artifact_name),
    )
    .unwrap();

    // SN 3: AveNode2 recupera el rol. Sin evento de contrato intermedio:
    // el fetch se relanza contra el ancla conservada.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // El refetch trae los mismos bytes anclados.
    let node2_v1_again =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v1, node2_v1_again);

    // Y evalúa: un fact commitea con el quorum de 2 evaluadores.
    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        subject_id.clone(),
        json!({"ModOne": {"data": 9}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 9, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Perder y recuperar el rol de evaluador conserva ancla Y bytes: la
// recuperación carga el artefacto local sin red. El commit final exige
// el voto de AveNode2 con la red inservible para él (Owner caído y el
// otro evaluador sirviendo basura), así que prueba que no hubo refetch.
async fn test_fetch_role_regain_local_first_no_network() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let node3_contracts = tempfile::tempdir().unwrap();
    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node3_dirs);
    node_running(&node3.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api, &node3.api])
            .await;

    // SN 1: AveNode2 y AveNode3 evaluadores (quorum Majority = 2 de 3);
    // AveNode3 además emisor.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"]
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ],
                        "validator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ],
                        "witness": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
                            },
                            {
                                "name": "AveNode3",
                                "namespace": [],
                                "quantity": 10
                            }
                        ],
                        "issuer": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ]
                    }
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
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Subject de AveNode3 (es quien emite el fact final con el Owner
    // caído: los facts de tracker solo los emite el dueño del subject)
    // y un fact v1: todos evalúan.
    let (subject_id, ..) = create_subject(
        &node3.api,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    get_subject(&node3.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &node3.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    get_subject(&node3.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2 y SN 3: AveNode2 pierde y recupera el rol de evaluador. Sus
    // bytes no se tocan.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // La red queda inservible para un refetch de AveNode2: el Owner se
    // apaga y el artefacto en disco de AveNode3 se corrompe (su caché de
    // serving está vacía: nunca ha servido).
    nodes[0].token.cancel();
    let mut owner = std::mem::take(&mut nodes[0].handler);
    join_all(owner.iter_mut()).await;

    let artifact_name = format!("{governance_id}_Example");
    fs::write(
        node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .join("contract.wasm"),
        b"garbage",
    )
    .unwrap();

    // AveNode3 emite un fact: el quorum exige a AveNode2, que solo puede
    // votar si evalúa con su artefacto LOCAL (cargado sin red).
    emit_fact(
        &node3.api,
        subject_id.clone(),
        json!({"ModTwo": {"data": 5}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(&node3.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 5, "three": 0}));

    let state = get_subject(&node2.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 5, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}
#[test(tokio::test)]
// Un evento que cambia el contrato de un schema y elimina OTRO schema a
// la vez: solo el schema vivo se promueve y ancla; el eliminado
// desaparece de las propiedades.
async fn test_gov_compile_change_and_remove_schema_same_event() {
    let contracts_dir = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    let schema_roles = |schema_id: &str| {
        json!({
            "schema_id": schema_id,
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
                        "quantity": 10
                    }
                ],
                "issuer": [
                    {
                        "name": "Owner",
                        "namespace": []
                    }
                ]
            }
        })
    };

    // SN 1: dos schemas con contrato.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "ExampleA",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "ExampleB",
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
            "schema": [
                schema_roles("ExampleA"),
                schema_roles("ExampleB")
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: un solo evento cambia el contrato de ExampleA a la v2 y
    // elimina ExampleB.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "ExampleA",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ],
            "remove": ["ExampleB"]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert_eq!(gov.version, 2);

    let schema_a = gov
        .schemas
        .get(&SchemaType::Type("ExampleA".to_owned()))
        .expect("el schema ExampleA debe existir");
    assert_eq!(schema_a.contract, EXAMPLE_CONTRACT_V2);
    assert!(
        !gov.schemas
            .contains_key(&SchemaType::Type("ExampleB".to_owned()))
    );

    // El artefacto promovido de ExampleA es el de la v2.
    let artifact_a = wait_artifact_bytes(
        contracts_dir.path(),
        &format!("{governance_id}_ExampleA"),
    )
    .await;
    assert!(!artifact_a.is_empty());

    // ExampleA evalúa con la v2 (ModThree=50 solo es válido en la v2).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "ExampleA", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node1.api).await.unwrap();
}
#[test(tokio::test)]
// La política de compilación Percentage(50) se respeta: con 4 compilers
// basta 1 firma de cada 2 (2 de 4) para commitear un alta de schema, y
// con solo 1 de 4 la request entra en RebootTimeOut sin commitear.
async fn test_gov_compile_quorum_percentage() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let mut compiler_nodes = Vec::new();
    for _ in 0..3 {
        let (node, mut node_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![RoutingNode {
                peer_id: nodes[0].api.peer_id().to_string(),
                address: vec![nodes[0].listen_address.clone()],
            }],
            always_accept: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut node_dirs);
        node_running(&node.api).await.unwrap();
        compiler_nodes.push(node);
    }

    let governance_id = create_and_authorize_governance(
        node1,
        compiler_nodes.iter().map(|n| &n.api).collect(),
    )
    .await;

    // SN 1: los tres nodos nuevos son compilers y testigos (4 compilers
    // en total contando al Owner).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": compiler_nodes[0].api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": compiler_nodes[1].api.public_key()
                },
                {
                    "name": "AveNode4",
                    "key": compiler_nodes[2].api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3", "AveNode4"],
                    "compiler": ["AveNode2", "AveNode3", "AveNode4"]
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    for node in &compiler_nodes {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    // SN 2: política de compilación Percentage(50): con 4 compilers el
    // quorum son 2 firmas.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "compile": {
                        "percentage": 50
                    }
                }
            }
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    for node in &compiler_nodes {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    // Caen AveNode3 y AveNode4: quedan 2 de 4 compilers, justo el 50%.
    for node in &compiler_nodes[1..] {
        node.token.cancel();
    }
    join_all(
        compiler_nodes[1..]
            .iter_mut()
            .flat_map(|n| n.handler.iter_mut()),
    )
    .await;

    // SN 3: alta de schema con contrato. El quorum Percentage(50) se
    // cubre con Owner y AveNode2 (con Majority necesitaría 3 y no
    // commitearía).
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

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        gov.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    // Cae también AveNode2: queda 1 de 4, por debajo del 50%. El alta de
    // un segundo schema no puede commitear.
    compiler_nodes[0].token.cancel();
    join_all(compiler_nodes[0].handler.iter_mut()).await;

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
                }
            ]
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        node1,
        request_id,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    let state = get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        !gov.schemas
            .contains_key(&SchemaType::Type("Example2".to_owned()))
    );
}
#[test(tokio::test)]
// Plan B de serving: con el único compiler (Owner) caído, un evaluador
// que ya tiene el artefacto v1 lo sirve a otro evaluador que se
// incorpora. Sin el serving del evaluador, AveNode3 no podría obtener
// el artefacto.
async fn test_fetch_plan_b_evaluator_serves_with_compilers_down() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let node1 = &nodes[0].api;

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let node2_contracts = tempfile::tempdir().unwrap();
    let (node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node2_dirs);
    node_running(&node2.api).await.unwrap();

    let node3_contracts = tempfile::tempdir().unwrap();
    let (node3, mut node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node3_dirs);
    node_running(&node3.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api]).await;

    // AveNode3 sincroniza la gobernanza con el Owner ya caído: su única
    // fuente posible es AveNode2 (testigo del gov desde SN1), así que se
    // autoriza con ambos como sync peers.
    node3
        .api
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(node1.public_key()).unwrap(),
                PublicKey::from_str(&node2.api.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();

    // SN 1: AveNode2 evaluador y testigo de la gobernanza; AveNode3 solo
    // evaluador. El único compiler es el Owner.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // AveNode2 sincroniza y fetcheada la v1 del Owner (único compiler).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // Cae el Owner: no queda ningún compiler vivo. AveNode3 solo puede
    // obtener la v1 por plan B (evaluador que ya la tiene).
    nodes[0].token.cancel();
    let mut owner = std::mem::take(&mut nodes[0].handler);
    join_all(owner.iter_mut()).await;

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v1, node3_v1);

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}
#[test(tokio::test)]
// Ciclo update+timeoff: dos schemas sin nadie que los sirva dejan al
// evaluador esperando (una sola ronda de gov update para ambos), el
// schema cuyo artefacto sí tiene sigue evaluando con normalidad y un
// alta sobre un schema sin artefacto responde Unavailable (la request
// entra en RebootTimeOut). Cuando el servidor vuelve a tener los bytes
// oficiales, el fetch se completa y la request rebootada commitea.
async fn test_fetch_unavailable_until_server_returns() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema "Stable" evaluado por ambos. AveNode2 lo fetcheada.
    // AveNode2 NO es testigo de la gobernanza a propósito: si lo fuera,
    // aplicaría SN 2 por distribución en el commit (antes de corromper
    // los bytes del Owner) y fetcheada Foo/Bar válidos. Así solo aplica
    // SN 2 cuando el test hace update_subject, con los bytes ya
    // corruptos.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Stable",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        },
        "schemas": {
            "add": [
                {
                    "id": "Stable",
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let stable_name = format!("{governance_id}_Stable");
    wait_artifact_bytes(node2_contracts.path(), &stable_name).await;

    // SN 2: se añaden "Foo" y "Bar", evaluados SOLO por AveNode2 (así el
    // Owner nunca los evalúa y no dispara su propia recompilación).
    let foo_bar_roles = |schema_id: &str| {
        json!({
            "schema_id": schema_id,
            "add": {
                "evaluator": [
                    {
                        "name": "AveNode2",
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
                        "quantity": 10
                    }
                ],
                "issuer": [
                    {
                        "name": "Owner",
                        "namespace": []
                    }
                ]
            }
        })
    };

    let json = json!({
        "roles": {
            "schema": [foo_bar_roles("Foo"), foo_bar_roles("Bar")]
        },
        "schemas": {
            "add": [
                {
                    "id": "Foo",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Bar",
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El Owner compiló Foo y Bar pero nadie se los ha pedido jamás: su
    // caché de serving está vacía. Movemos los directorios de artefacto
    // (no se corrompen los bytes: esos bytes se servirían y quedarían
    // 300s en la caché de serving — SERVING_CACHE_TTL — envenenando los
    // fetches posteriores; con el directorio ausente el serve devuelve
    // None y NO rellena la caché, así que al restaurar el siguiente
    // fetch lee los bytes buenos de disco).
    let foo_name = format!("{governance_id}_Foo");
    let bar_name = format!("{governance_id}_Bar");
    let foo_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&foo_name);
    let bar_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&bar_name);
    let foo_bytes = fs::read(foo_dir.join("contract.wasm")).unwrap();
    let bar_bytes = fs::read(bar_dir.join("contract.wasm")).unwrap();
    let foo_hidden = foo_dir.with_extension("bak");
    let bar_hidden = bar_dir.with_extension("bak");
    fs::rename(&foo_dir, &foo_hidden).unwrap();
    fs::rename(&bar_dir, &bar_hidden).unwrap();

    // AveNode2 aplica SN 2: necesita Foo y Bar, pero nadie sirve bytes
    // válidos. El fetch queda en ciclo de reintentos.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&foo_name)
            .exists()
    );
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&bar_name)
            .exists()
    );

    // El schema con artefacto local sigue evaluando: un fact de Stable
    // commitea con el voto de AveNode2 mientras Foo y Bar están
    // bloqueados.
    let (stable_subject, ..) =
        create_subject(&node1.api, governance_id.clone(), "Stable", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, stable_subject.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &node1.api,
        stable_subject.clone(),
        json!({"ModOne": {"data": 9}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node2.api, stable_subject.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 9, "two": 0, "three": 0}));

    // Los Create de tracker NO pasan por evaluación (el init_value se
    // verifica en la fase de compilación del schema, no por subject), así
    // que el alta de un subject Foo commitea aunque AveNode2 no tenga el
    // artefacto. Lo que no puede commitear es un FACT: la evaluación la
    // hace AveNode2, que no tiene módulo → Unavailable → RebootTimeOut.
    let (foo_subject, ..) =
        create_subject(&node1.api, governance_id.clone(), "Foo", "", true)
            .await
            .unwrap();

    let foo_request = emit_fact(
        &node1.api,
        foo_subject.clone(),
        json!({"ModOne": {"data": 3}}),
        false,
    )
    .await
    .unwrap();

    wait_request_state(
        &node1.api,
        foo_request,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // El servidor vuelve a tener los artefactos oficiales: el ciclo de
    // reintentos de AveNode2 completa ambos fetches verificados contra
    // el ancla.
    fs::rename(&foo_hidden, &foo_dir).unwrap();
    fs::rename(&bar_hidden, &bar_dir).unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &foo_name, &foo_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &bar_name, &bar_bytes)
        .await;

    // La request rebootada evalúa Foo y commitea.
    let state = get_subject(&node1.api, foo_subject.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 3, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Un peer corrupto sirve bytes que no casan con el ancla: el receptor
// los descarta (warn) y no los escribe en disco; cuando un servidor con
// los bytes oficiales vuelve a estar disponible, el fetch se completa.
async fn test_fetch_corrupt_peer_hash_mismatch_failover() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    // SN 1: AveNode2 pasa a ser compiler y testigo de la gobernanza.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: alta del schema. Los compilers son Owner y AveNode2: ambos
    // compilan la v1 localmente (nadie la fetcheada, así que ninguna
    // caché de serving se llena y la corrupción en disco es efectiva).
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Escenario: AveNode2 es el peer corrupto (sirve bytes que no casan
    // con el ancla → el receptor los descarta sin escribir en disco) y el
    // Owner está no disponible (artefacto ausente → serve devuelve None).
    // OJO: no se corrompen los bytes del Owner — esos bytes se servirían
    // y quedarían 300s en su caché de serving (SERVING_CACHE_TTL,
    // worker.rs), envenenando los fetches posteriores a la restauración;
    // con el directorio ausente la caché no se rellena.
    let artifact_name = format!("{governance_id}_Example");
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node2_wasm = node2_contracts
        .path()
        .join("contracts")
        .join(&artifact_name)
        .join("contract.wasm");
    let node1_v1 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();
    fs::write(&node2_wasm, b"garbage").unwrap();

    // AveNode3 aplica SN 2 y necesita la v1: todos los bytes que recibe
    // fallan la verificación contra el ancla y se descartan.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists()
    );

    // El Owner vuelve a estar disponible: el siguiente intento de
    // AveNode3 completa el fetch verificado contra el ancla.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // AveNode3 evalúa con el artefacto fetcheado: un fact commitea con
    // el quórum de los dos evaluadores.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node3.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 9}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node3.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 9, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}
#[test(tokio::test)]
// Recuperación en arranque por la vía FETCH (evaluador): artefacto
// intacto → no hay refetch (arranca aislado y los bytes no cambian);
// artefacto ausente → refetch verificado contra el ancla; artefacto
// manipulado en disco (wasm corrupto y cwasm borrado) → se descarta y
// se refetcheada.
async fn test_fetch_startup_recovery_absent_tampered_intact() {
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
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

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: tres schemas con contrato, evaluados por ambos. AveNode2 los
    // fetcheada del Owner (único compiler).
    let schema_roles = |schema_id: &str| {
        json!({
            "schema_id": schema_id,
            "add": {
                "evaluator": [
                    {
                        "name": "Owner",
                        "namespace": []
                    },
                    {
                        "name": "AveNode2",
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
                        "quantity": 10
                    }
                ],
                "issuer": [
                    {
                        "name": "Owner",
                        "namespace": []
                    }
                ]
            }
        })
    };

    let schema_add = |schema_id: &str| {
        json!({
            "id": schema_id,
            "contract": EXAMPLE_CONTRACT,
            "initial_value": {
                "one": 0,
                "two": 0,
                "three": 0
            }
        })
    };

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
                }
            },
            "schema": [
                schema_roles("Alpha"),
                schema_roles("Beta"),
                schema_roles("Gamma")
            ]
        },
        "schemas": {
            "add": [
                schema_add("Alpha"),
                schema_add("Beta"),
                schema_add("Gamma")
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let alpha_name = format!("{governance_id}_Alpha");
    let beta_name = format!("{governance_id}_Beta");
    let gamma_name = format!("{governance_id}_Gamma");
    let alpha_bytes =
        wait_artifact_bytes(node2_contracts.path(), &alpha_name).await;
    let beta_bytes =
        wait_artifact_bytes(node2_contracts.path(), &beta_name).await;
    let gamma_bytes =
        wait_artifact_bytes(node2_contracts.path(), &gamma_name).await;

    // CASO 1 (intacto): reinicio aislado de la red. Todo está en disco:
    // no hay refetch posible y el nodo arranca con los mismos bytes.
    // (Bootstrap sin peers: un Addressable sin boot nodes muere con
    // NoBootstrapNode — network/worker.rs — y el nodo no arranca.)
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &alpha_name, &alpha_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &beta_name, &beta_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &gamma_name, &gamma_bytes)
        .await;

    // CASO 2 (ausente): Beta borrado del disco. Al arrancar con red, el
    // nodo lo refetcheada verificado contra el ancla.
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    fs::remove_dir_all(
        node2_contracts.path().join("contracts").join(&beta_name),
    )
    .unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &beta_name, &beta_bytes)
        .await;

    // CASO 3 (manipulado): el wasm de Gamma está corrupto y su cwasm
    // borrado. El arranque detecta el mismatch contra el ancla, descarta
    // el artefacto y lo refetcheada.
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let gamma_dir = node2_contracts.path().join("contracts").join(&gamma_name);
    fs::write(gamma_dir.join("contract.wasm"), b"garbage").unwrap();
    fs::remove_file(gamma_dir.join("contract.cwasm")).unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &gamma_name, &gamma_bytes)
        .await;

    // Los otros artefactos no se han tocado en ningún reinicio.
    wait_artifact_bytes_eq(node2_contracts.path(), &alpha_name, &alpha_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &beta_name, &beta_bytes)
        .await;

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Nodo con rol dual compiler+evaluador: compila la v1 y la sirve como
// compiler (plan A) a otro evaluador. Tras perder el rol de compiler y
// commitearse un cambio de contrato, obtiene la v2 por la vía fetch
// verificada contra el ancla, evalúa con ella y la sirve como evaluador
// (plan B) cuando el único compiler está caído.
async fn test_dual_role_serves_plan_a_and_b() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();
    let node4_contracts = tempfile::tempdir().unwrap();

    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let node2_contracts_path = node2_contracts.path().to_path_buf();
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts_path),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let (node4, _node4_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node4_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node4.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    // AveNode4 hace su primera sincronización de la gobernanza con el
    // Owner ya caído: su única fuente posible es AveNode2 (testigo del
    // gov desde SN1), así que se autoriza con ambos como sync peers.
    node4
        .api
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(node1.api.public_key()).unwrap(),
                PublicKey::from_str(&node2.api.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();

    // SN 1: AveNode2 se convierte en compiler y testigo de la
    // gobernanza (todavía no hay schemas).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                },
                {
                    "name": "AveNode4",
                    "key": node4.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: alta del schema. Los compilers son Owner y AveNode2: ambos
    // compilan la v1 localmente. Nadie fetcheada, así que la caché de
    // serving del Owner está vacía.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
                                "namespace": []
                            },
                            {
                                "name": "AveNode4",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // PLAN A: el Owner queda con el wasm corrupto en disco (nunca ha
    // servido: su caché está vacía). AveNode3 solo puede obtener la v1
    // de AveNode2, que la sirve como compiler.
    let node1_wasm = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name)
        .join("contract.wasm");
    fs::write(&node1_wasm, b"garbage").unwrap();

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v1, node3_v1);

    // SN 3: AveNode2 pierde el rol de compiler y AveNode3 el de
    // evaluador. Sin fase compile.
    let json = json!({
        "roles": {
            "governance": {
                "remove": {
                    "compiler": ["AveNode2"]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // SN 4: cambio de contrato a la v2. El único compiler es el Owner;
    // AveNode2, ya solo evaluador, obtiene la v2 por fetch verificado
    // contra el ancla.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // La v1 sigue en disco hasta que el Reconcile la descarta y el fetch
    // de la v2 (verificada contra el ancla) la reemplaza: esperar a que
    // los bytes cambien, no a que el fichero simplemente exista.
    let node2_v2 = {
        let path = node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .join("contract.wasm");
        let mut bytes = Vec::new();
        for _ in 0..100 {
            if let Ok(read) = fs::read(&path)
                && read != node2_v1
            {
                bytes = read;
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        assert!(
            !bytes.is_empty(),
            "timeout waiting for v2 artifact {}",
            path.display()
        );
        bytes
    };

    // AveNode2 evalúa con la v2 fetcheada: un fact solo válido con la
    // v2 (ModThree=50) commitea con los votos del Owner y AveNode2
    // (quórum 2 de 3; AveNode4 está desactualizado y no hace falta).
    let (subject_id, ..) = create_subject(
        &node1.api,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node2.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    // PLAN B: cae el Owner (único compiler). AveNode4 se incorpora y
    // necesita la v2; AveNode3 se quedó en la v1 y ya no es evaluador,
    // así que el único servidor posible es AveNode2, ahora solo
    // evaluador con el artefacto verificado.
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    node4
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node4.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    let node4_v2 =
        wait_artifact_bytes(node4_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v2, node4_v2);

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
    node_running(&node4.api).await.unwrap();
}
#[test(tokio::test)]
// Fetch happy path: un evaluador sin rol de compiler obtiene el
// artefacto de la red tras el alta del schema (probe → fetch → bytes
// verificados contra el ancla del ledger antes de persistirse) y
// evalúa con él: el fact solo commitea si AveNode2 vota con el
// artefacto fetcheado (quórum Majority sobre los dos evaluadores).
async fn test_fetch_happy_path_evaluator_fetches_and_evaluates() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example (contrato v1). AveNode2 evalúa pero NO
    // compila: solo puede obtener el artefacto por fetch.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // El fetch completa: artefacto en disco en AveNode2 con bytes
    // idénticos a los del compiler (el ancla del ledger garantiza que
    // son los bytes que el quórum firmó).
    let artifact_name = format!("{governance_id}_Example");
    let node2_bytes =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    let node1_bytes =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    assert_eq!(node2_bytes, node1_bytes);

    // AveNode2 evalúa con el artefacto fetcheado: el fact necesita los
    // dos votos (Majority de 2) y commitea.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Tras el commit de un cambio de contrato los evaluadores obtienen el
// artefacto NUEVO, nunca el viejo: la promoción invalida la caché de
// serving y el serving se bloquea durante el apply (ambos internos; lo
// observable: los bytes fetcheados son los de la v2 y un fact que la
// v1 rechazaría commitea con el voto del evaluador que fetcheada).
async fn test_fetch_after_contract_change_serves_new_artifact() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example (contrato v1), AveNode2 evaluador.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: cambio de contrato a la v2.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_v2 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    assert_ne!(node1_v2, node2_v1);

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El fetch trae los bytes de la v2 (verificados contra el ancla
    // nueva), no los de la v1 que ya tenía.
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // Un fact que la v1 rechazaría (ModThree=50) commitea: ambos
    // evaluadores votan con el módulo v2.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Whitelist de fetch: un miembro sin rol de evaluador ni compiler no
// recibe nada (silencio); al ganar el rol de evaluador el fetch arranca
// y obtiene el artefacto; al perderlo, los cambios de contrato
// posteriores ya NO se fetcheada — los bytes v1 se conservan en disco
// (la retención de artefactos tras la pérdida de rol es por diseño).
async fn test_fetch_whitelist_role_gain_and_loss() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: AveNode2 es miembro pero SIN roles de schema. Todos los
    // roles de Example son del Owner.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Silencio: AveNode2 no es evaluador, nadie le sirve (ni él pide).
    let artifact_name = format!("{governance_id}_Example");
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists()
    );

    // SN 2: AveNode2 gana el rol de evaluador → el fetch arranca.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v1, node1_v1);

    // SN 3: AveNode2 pierde el rol de evaluador.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // SN 4: cambio de contrato a la v2. AveNode2, ya sin rol, NO lo
    // fetcheada aunque aplique el evento.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // Los bytes en disco siguen siendo los de la v1 (retenidos, sin
    // refetch): el nodo sin rol queda silenciado.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let node2_bytes =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(node2_bytes, node1_v1);

    // Control: la red sigue operativa — un fact v2-only commitea con el
    // Owner como único evaluador.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Regresión de BUG-010: los eventos de gobernanza que NO tocan el
// contrato no resetean un fetch en vuelo. Escenario: el fetch de la v2
// queda estancado (el servidor no puede servir), tres eventos ajenos
// al contrato commitean y AveNode2 los aplica con el fetch en vuelo;
// cuando el servidor vuelve, el fetch completa con los bytes de la v2.
// La ausencia de reset es interna (no observable desde fuera): lo que
// se pincha es la supervivencia del fetch bajo carga de eventos ajenos
// (con BUG-010, cada evento reseteaba el fetch a cero → starvation).
async fn test_fetch_survives_unrelated_gov_events() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador (fetcheada la v1).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: cambio de contrato a la v2. La promoción limpia la caché de
    // serving del Owner; la v2 aún no se ha servido a nadie, así que
    // mover el directorio deja al Owner sin poder servir (serve None,
    // sin rellenar la caché).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_v2 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    assert_ne!(node1_v2, node2_v1);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // AveNode2 aplica SN 2: el fetch de la v2 arranca y queda estancado
    // (el único servidor no sirve).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3/4/5: tres eventos ajenos al contrato (altas de miembros sin
    // roles) commitean mientras el fetch está en vuelo.
    for name in ["AveNode3", "AveNode4", "AveNode5"] {
        let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();
        let json = json!({
            "members": {
                "add": [
                    {
                        "name": name,
                        "key": key
                    }
                ]
            }
        });
        emit_fact(&node1.api, governance_id.clone(), json, true)
            .await
            .unwrap();
    }

    get_subject(&node1.api, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    // AveNode2 aplica los tres eventos con el fetch en vuelo: el fetch
    // NO se resetea (BUG-010).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    // El servidor vuelve: el fetch superviviente completa con los bytes
    // de la v2.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // Y evalúa con ella: un fact v2-only commitea con ambos votos.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Complemento de TEST-012 (BUG-010): un cambio de ROLES que no toca
// los peers que el fetch está usando (alta de un testigo del schema:
// los testigos no son servidores ni requesters de artefactos) tampoco
// resetea el fetch en vuelo; al volver el servidor, completa con los
// bytes de la v2.
async fn test_fetch_survives_irrelevant_role_change() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador (fetcheada la v1).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: cambio de contrato a la v2; el Owner queda sin poder servir
    // (directorio movido, caché de serving vacía para la v2).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_v2 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // AveNode2 aplica SN 2: fetch de la v2 en vuelo y estancado.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: alta de un testigo del schema — cambio de roles que NO toca
    // los peers del fetch (los testigos no sirven ni piden artefactos).
    let witness_key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode3",
                    "key": witness_key
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "witness": [
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // AveNode2 aplica el cambio de roles con el fetch en vuelo.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // El servidor vuelve: el fetch completa con los bytes de la v2.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// Un nodo NUNCA evalúa con el módulo viejo: tras el commit de la v2,
// AveNode2 (módulo v1 evictado al aplicar el cambio, fetch de la v2
// estancado) responde Unavailable al fact v2-only en lugar de votar
// con el módulo v1 — que lo rechazaría y abriría un Reboot(Diff) entre
// nodos honestos. Cuando el servidor vuelve, el fetch completa y la
// request rebootada commitea OK.
async fn test_never_evaluates_stale_module_during_fetch() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // Subject y un fact v1: AveNode2 evalúa con la v1 (su módulo está
    // cargado en memoria).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // SN 2: cambio de contrato a la v2. El Owner queda sin poder
    // servirla (directorio movido, caché de serving vacía para la v2).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_v2 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // AveNode2 aplica SN 2: su módulo v1 queda evictado (el contrato
    // cambió) y el fetch de la v2 queda estancado.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Un fact v2-only (la v1 lo rechaza con error de contrato): el
    // Owner vota OK con la v2; AveNode2 debe responder Unavailable — si
    // evaluara con el módulo v1 votaría ERROR y la request acabaría en
    // Reboot(Diff) o peor. La request entra en RebootTimeOut.
    let fact_request = emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        false,
    )
    .await
    .unwrap();

    wait_request_state(
        &node1.api,
        fact_request,
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // El servidor vuelve: AveNode2 fetcheada la v2 y la request
    // rebootada commitea con ambos votos OK.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// El requester pierde el rol de evaluador con el fetch en vuelo: los
// servidores le guardan silencio (whitelist) y el fetch se cancela; el
// nodo converge (gobernanza al día, sin artefacto nuevo, sin cuelgue)
// y al recuperar el rol el fetch arranca de nuevo y completa.
async fn test_fetch_requester_loses_role_mid_cycle() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador (fetcheada la v1).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    // Sync point: node2 fetched v1 before the contract change.
    wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: cambio de contrato a la v2; el Owner queda sin poder servir
    // (directorio movido, caché de serving vacía para la v2).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_v2 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // AveNode2 aplica SN 2: fetch de la v2 en vuelo y estancado.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: AveNode2 pierde el rol de evaluador CON EL FETCH EN VUELO.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // El servidor vuelve, pero AveNode2 ya no es evaluador: silencio.
    // La v1 fue descartada en disco al commitear SN 2 (los bytes que no
    // verifican contra el ancla nueva no sobreviven:
    // CompilerSupport::discard_persisted_artifact) y la v2 no puede
    // llegar sin el rol: el artefacto NO existe.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "sin rol de evaluador el fetch no completa: la v1 se descarto al \
         cambiar el contrato y la v2 no debe llegar"
    );

    // SN 4: AveNode2 recupera el rol → el fetch arranca de nuevo y
    // completa con los bytes de la v2.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // Y vuelve a evaluar: un fact v2-only commitea con ambos votos.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// BUG-010 (whitelist viva): un cambio de whitelist que EXPULSA a los
// peers que el fetch estaba usando fuerza un re-probe con el set en
// vivo; el fetch completa desde los compiladores nuevos (que compilan
// la v2 localmente al ganar el rol). Sin bucle de resets ni starvation.
async fn test_fetch_reprobe_when_whitelist_drops_serving_peers() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();
    let node4_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    // AveNode2: compiler del schema desde el inicio; testigo de la
    // gobernanza para aplicar los eventos en el commit.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    // AveNode3: evaluador (el que fetcheada).
    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    // AveNode4: futuro compiler; testigo de la gobernanza para aplicar
    // el cambio de roles en el commit y compilar la v2 al ganar el rol.
    let (node4, _node4_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node4_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node4.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api, &node4.api],
    )
    .await;

    // SN 1: miembros y roles de gobernanza. AveNode2 es compiler;
    // AveNode4 aún no (lo será en SN 4).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                },
                {
                    "name": "AveNode4",
                    "key": node4.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode4"],
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: alta del schema con contrato v1. Compilan Owner y AveNode2.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // AveNode3 aplica SN 2 y fetcheada la v1 (baseline).
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;

    // SN 3: cambio de contrato a la v2. Compilan Owner y AveNode2;
    // AveNode2 la aplica en el commit (es gov witness).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_v2 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    assert_ne!(node1_v2, node3_v1);

    // Los DOS compilers quedan sin poder servir la v2 (directorios
    // movidos; la v2 nunca se sirvió, cachés de serving vacías).
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();
    let node2_dir = node2_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node2_hidden = node2_dir.with_extension("bak");
    fs::rename(&node2_dir, &node2_hidden).unwrap();

    // AveNode3 aplica SN 3: fetch de la v2 en vuelo, estancado (los
    // peers en uso son Owner y AveNode2, ambos sin servir).
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // SN 4: la whitelist cambia — AveNode2 deja de ser compiler y
    // AveNode4 lo gana. El fetch debe re-probar con el set en vivo
    // {Owner, AveNode4}: AveNode4 compila la v2 localmente al ganar el
    // rol y la sirve.
    let json = json!({
        "roles": {
            "governance": {
                "remove": {
                    "compiler": ["AveNode2"]
                },
                "add": {
                    "compiler": ["AveNode4"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // AveNode4 (gov witness) aplicó SN 4 en el commit y compila la v2;
    // AveNode3 aplica SN 4 → re-probe → fetch completa desde AveNode4.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // El fetch completa con los bytes anclados de la v2 pese a que los
    // dos servidores originales siguen sin servir.
    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // AveNode3 evalúa con la v2: un fact v2-only commitea.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
    node_running(&node4.api).await.unwrap();
}
#[test(tokio::test)]
// El purge total (`delete_subject` en safe mode) elimina los artefactos
// en disco y purga el registro de contratos (anclas incluidas). Tras el
// purge el nodo resincroniza la gobernanza desde cero: las anclas se
// re-derivan del ledger al aplicar los eventos, el artefacto se
// refetcheada verificado y el nodo vuelve a evaluar.
async fn test_total_purge_removes_anchors_and_artifacts() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (mut node2, mut node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador (fetcheada la v1).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // Un subject con un fact: AveNode2 evalúa (su voto es necesario).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // El tracker impide borrar la gobernanza (GovernanceHasTrackers):
    // se borra primero el tracker. Ambos borrados requieren safe mode:
    // reinicio de AveNode2 con safe_mode activado.
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2_safe, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        safe_mode: true,
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node2_dirs.append(&mut new_dirs);
    node_running(&node2_safe.api).await.unwrap();

    // AveNode2 no tiene el tracker (nunca fue testigo): el borrado de
    // la gobernanza en SU copia local no exige borrar trackers.
    node2_safe
        .api
        .delete_subject(governance_id.clone())
        .await
        .unwrap();

    // El purge elimina el artefacto del disco y la gobernanza local.
    let artifact_dir = node2_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    for _ in 0..100 {
        if !artifact_dir.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        !artifact_dir.exists(),
        "el purge debe eliminar el artefacto del disco"
    );
    assert!(
        node2_safe
            .api
            .get_subject_state(governance_id.clone())
            .await
            .is_err(),
        "el purge debe eliminar la gobernanza local"
    );

    // Resincronización desde cero: las anclas se re-derivan del ledger
    // al aplicar, el artefacto se refetcheada verificado y AveNode2
    // vuelve a evaluar (su voto es necesario para el fact).
    // En safe mode las operaciones mutantes están deshabilitadas:
    // reinicio de vuelta a modo normal (mismas keys/dbs/contracts).
    let mut node2_safe = node2_safe;
    node2_safe.token.cancel();
    join_all(node2_safe.handler.iter_mut()).await;

    let (node2_safe, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(node2_safe.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node2_dirs.append(&mut new_dirs);
    node_running(&node2_safe.api).await.unwrap();

    node2_safe
        .api
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(node1.api.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    node2_safe
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2_safe.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let refetched =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(refetched, node2_v1);

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 9}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 9, "two": 0, "three": 0}));

    node_running(&node2_safe.api).await.unwrap();
}
#[test(tokio::test)]
// Una request que compila con éxito pero es RECHAZADA después (aquí: en
// aprobación) nunca promociona su staging: el sweep lo elimina al
// abortar la request, el artefacto oficial no aparece, la versión de la
// gobernanza no avanza y una request posterior del mismo tipo compila y
// commitea con normalidad (el staging del evento fallido no es visible
// para requests posteriores). El boot sweep de staging huérfano de un
// crash queda cubierto estructuralmente por los tests
// `test_gov_compile_staging_*` existentes; aquí se pincha el camino de
// rechazo post-compilación.
async fn test_staging_swept_after_post_compile_rejection() {
    let node1_contracts = tempfile::tempdir().unwrap();

    // always_accept: false → los facts de gobernanza necesitan
    // aprobación manual del Owner (approver por defecto).
    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // Evento 1: alta del schema Example con contrato. Compila y evalúa
    // bien, pero queda pendiente de aprobación.
    let json = json!({
        "roles": {
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    // La compilación ya ocurrió: el staging existe y el artefacto
    // oficial NO (la promoción solo ocurre en el commit). OJO: el
    // staging vive en la RAÍZ de contracts_path (`<gov>_temp_staging_…`,
    // compilation/worker.rs), los oficiales en el subdir `contracts/`.
    let artifact_name = format!("{governance_id}_Example");
    let staging_prefix = format!("{governance_id}_temp_staging_Example_");
    let staging_exists = || {
        fs::read_dir(node1_contracts.path())
            .map(|entries| {
                entries.filter_map(|e| e.ok()).any(|e| {
                    e.file_name().to_string_lossy().starts_with(&staging_prefix)
                })
            })
            .unwrap_or(false)
    };
    for _ in 0..100 {
        if staging_exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        staging_exists(),
        "el staging de Example debe existir con la request en aprobación"
    );
    assert!(
        !node1_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "el artefacto oficial no debe existir antes del commit"
    );

    // El Owner rechaza la aprobación: la request aborta y el sweep
    // elimina el staging.
    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !fs::read_dir(node1_contracts.path())
            .map(|entries| {
                entries.filter_map(|e| e.ok()).any(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .contains("_temp_staging_")
                })
            })
            .unwrap_or(false),
        "el sweep debe eliminar el staging al abortar la request"
    );
    assert!(
        !node1_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "el artefacto oficial no debe existir tras el rechazo"
    );

    // La gobernanza no avanza de versión (el evento no se aplicó).
    let state = get_subject(&node1.api, governance_id.clone(), None, true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert_eq!(gov.version, 0);
    assert!(!gov.schemas.contains_key(&SchemaType::Type("Example".to_owned())));

    // Una request posterior del mismo tipo compila de cero y commitea
    // con normalidad: el staging del evento fallido no le es visible.
    let json = json!({
        "roles": {
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), None, true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert_eq!(gov.version, 1);
    assert!(gov.schemas.contains_key(&SchemaType::Type("Example".to_owned())));

    // El artefacto oficial aparece (promoción en el commit) y evalúa.
    wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 4}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 4, "two": 0, "three": 0}));

    node_running(&node1.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-008: un evaluador promovido a compiler con un fetch en vuelo
// CANCELA el fetch: los compilers nunca fetchean, compilan localmente.
// Con el único servidor incapaz de servir la v2 (directorio movido, sin
// envenenar su caché de serving), el artefacto de la v2 solo puede
// aparecer en AveNode2 por compilación local verificada contra el ancla
// tras la promoción.
async fn test_fetch_role_promotion_to_compiler_cancels_fetch() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador (fetchea la v1).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: cambio de contrato a la v2; el Owner compila y commitea.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El Owner queda sin poder servir la v2 (directorio movido: serve
    // devuelve None sin rellenar la caché de serving).
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_v2 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // AveNode2 aplica SN 2: descarta la v1 (no verifica contra el ancla
    // nueva) y arranca el fetch de la v2, estancado sin servidor.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "la v1 se descarta al cambiar el ancla y la v2 no puede llegar \
         sin servidor"
    );

    // SN 3: AveNode2 promovido a compiler → cancela el fetch y compila
    // localmente (los compilers nunca fetchean).
    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // Sin servidor alguno, la v2 aparece en AveNode2: solo pudo salir de
    // una compilación local verificada contra el ancla (determinista).
    let node2_v2 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(
        node2_v2, node1_v2,
        "la compilación local reproduce los bytes anclados"
    );
    assert_ne!(node2_v2, node2_v1);

    // Y evalúa con el módulo compilado: un fact v2-only commitea con su
    // voto (Majority de 2 evaluadores).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    fs::rename(&node1_hidden, &node1_dir).unwrap();
    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-009 (alcance determinista): un servidor expulsado del rol de
// evaluador deja de servir de inmediato (whitelist en caliente). AveNode3
// fetcheó la v1 de AveNode2 con el Owner sin servir; cuando AveNode2 es
// expulsado y AveNode3 pierde su artefacto local, el refetch queda
// estancado — el peer expulsado no sirve ni un byte más — hasta que el
// Owner vuelve a poder servir. (La negociación de versión/whitelist del
// ciclo es interna; lo observable es el silencio del peer expulsado.)
async fn test_fetch_server_goes_silent_on_role_loss() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();
    let node3_local = tempfile::tempdir().unwrap();
    let node3_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        local_db: Some(node3_local.path().to_path_buf()),
        ext_db: Some(node3_ext.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api, &node3.api])
            .await;

    // SN 1: schema Example v1; AveNode2 evaluador, AveNode3 solo miembro.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: AveNode3 gana el rol de evaluador.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // AveNode2 aplica SN 2 ANTES de que AveNode3 fetchee: la gate de
    // serving exige que el SERVIDOR conozca el rol del requester (si
    // AveNode2 se queda en SN1 rechaza los probes de AveNode3 como
    // "not an evaluator").
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El Owner no puede servir: AveNode3 fetcheará de AveNode2 (plan B).
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(
        node3_v1, node2_v1,
        "AveNode2 sirvió la v1 a AveNode3 por plan B"
    );

    // SN 3: AveNode2 pierde el rol de evaluador (expulsado como
    // servidor).
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "evaluator": [
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // AveNode2 aplica su expulsión (deja de servir). AveNode3 NO aplica
    // SN 3: su whitelist sigue incluyendo a AveNode2, así que su refetch
    // lo probará y comprobará el silencio del expulsado.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // AveNode3 pierde su artefacto local y REINICIA: la recuperación de
    // arranque (ancla v1, artefacto ausente) dispara el refetch. (En
    // caliente no habría trigger: el reconcile con el contrato sin
    // cambios no re-chequea el disco — "already available, skipping".)
    fs::remove_dir_all(
        node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name),
    )
    .unwrap();

    let (mut node3, _node3_dirs) = (node3, _node3_dirs);
    node3.token.cancel();
    join_all(node3.handler.iter_mut()).await;

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node3.keys.clone()),
        local_db: Some(node3_local.path().to_path_buf()),
        ext_db: Some(node3_ext.path().to_path_buf()),
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    // El refetch solo puede venir del peer expulsado (silencio) o del
    // Owner (oculto): estancado.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "el peer expulsado no sirve: el refetch queda estancado"
    );

    // El Owner vuelve a poder servir: el refetch completa con la v1.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    let node3_refetch =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(node3_refetch, node2_v1);

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-057: el staging NUNCA se sirve pre-commit. Con el cambio de
// contrato compilado y pendiente de aprobación (staging de la v2 en la
// raíz de contracts_path, oficial todavía v1), un fetch recibe los bytes
// de la V1 oficial: serve_official_artifact solo mira el área oficial.
async fn test_staging_never_served_pre_commit() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    // always_accept por defecto (false): los facts de gobernanza
    // necesitan aprobación manual del Owner.
    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1 (aprobación manual).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();
    wait_request_state(
        &node1.api,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();
    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // Fuerza un refetch posterior: borra el artefacto local de AveNode2.
    fs::remove_dir_all(
        node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name),
    )
    .unwrap();

    // SN 2: cambio de contrato a la v2. Compila y queda PENDIENTE de
    // aprobación: el staging de la v2 existe en el Owner, el oficial
    // sigue siendo la v1.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();
    wait_request_state(
        &node1.api,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    let staging_prefix = format!("{governance_id}_temp_staging_Example_");
    let staging_exists = || {
        fs::read_dir(node1_contracts.path())
            .map(|entries| {
                entries.filter_map(|e| e.ok()).any(|e| {
                    e.file_name().to_string_lossy().starts_with(&staging_prefix)
                })
            })
            .unwrap_or(false)
    };
    assert!(
        staging_exists(),
        "el staging de la v2 debe existir con la request en aprobación"
    );
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "el oficial v1 sigue en disco mientras el cambio está pendiente"
    );

    // Refetch de AveNode2 con el commit PENDIENTE: el reinicio dispara la
    // recuperación (ancla v1, artefacto ausente → fetch). El Owner sirve
    // el oficial: bytes de la V1, nunca el staging de la v2.
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let refetched =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(
        refetched, node2_v1,
        "el staging nunca se sirve: el fetch recibe la v1 oficial"
    );

    // Aprueba el cambio: la v2 se promociona y AveNode2 la fetcheada.
    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_v2 = fs::read(
        node1_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .join("contract.wasm"),
    )
    .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-035 (alcance determinista): un nodo que se apaga tras aplicar un
// cambio de contrato con el fetch del nuevo artefacto AÚN PENDIENTE
// arranca consistente (BUG-009 A+B): el ancla de la v2 ya está
// registrada (se registra al aplicar el evento), el artefacto ausente se
// refetchea verificado contra ella y el nodo vuelve a evaluar. La
// ventana exacta entre persistencia del evento y registro del ancla no
// es alcanzable sin hooks; aquí se pincha la propiedad de recuperación.
async fn test_boot_recovery_after_shutdown_with_pending_fetch() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador (fetchea la v1).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: cambio de contrato a la v2; el Owner compila y commitea.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_v2 = fs::read(node1_dir.join("contract.wasm")).unwrap();

    // AveNode2 aplica SN 2 (ancla v2 registrada, v1 descartada) pero su
    // fetch de la v2 queda pendiente: el Owner no puede servir.
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Apagado con el fetch en vuelo; el Owner vuelve a poder servir.
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    // Arranque: ancla v2 presente, artefacto ausente → refetch anclado.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // Y evalúa con la v2: un fact v2-only commitea con su voto.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-058: la pérdida del rol de compiler RETIENE artefacto y ancla; al
// recuperarlo con el pool MUERTO el nodo sirve en plan A desde disco con
// cero builds (cualquier intento de build fallaría: endpoints a un
// puerto muerto). AveNode2 fetchea la v1 como evaluador, gana y pierde
// el rol de compiler, lo recupera, y con el Owner apagado sirve la v1 a
// AveNode3.
async fn test_compiler_role_regain_dead_pool_serves_from_disk() {
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
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

    // AveNode2 con el pool muerto desde el principio.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // AveNode3 sincronizará el gov con el Owner ya apagado: sus sync
    // peers posibles son el Owner y AveNode2 (testigo del gov).
    node3
        .api
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(node1.api.public_key()).unwrap(),
                PublicKey::from_str(&node2.api.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();

    // SN 1: schema Example v1; AveNode2 evaluador + testigo del gov (y
    // del schema) — fetchea la v1 con el pool muerto (el fetch no usa
    // pool).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
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
                            },
                            {
                                "name": "AveNode2",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: AveNode2 gana el rol de compiler (artefacto ya en disco:
    // carga local verificada contra el ancla, cero builds aunque el pool
    // esté muerto).
    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node2_v1)
        .await;

    // SN 3: AveNode2 PIERDE el rol de compiler → artefacto retenido.
    let json = json!({
        "roles": {
            "governance": {
                "remove": {
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node2_v1)
        .await;

    // SN 4: AveNode2 recupera el rol de compiler. SN 5: AveNode3 gana el
    // rol de evaluador del schema.
    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    // El Owner se apaga: el único compiler vivo es AveNode2, con el pool
    // muerto — si intentara compilar cualquier cosa fallaría.
    let (mut node1, _node1_dirs) = (node1, _node1_dirs);
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    // AveNode3 sincroniza desde AveNode2 y fetchea la v1 en plan A:
    // servida desde el disco de AveNode2 con cero builds.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(
        node3_v1, node2_v1,
        "AveNode2 sirvió la v1 desde disco en plan A con el pool muerto"
    );

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-059: ráfaga de fetch — tres evaluadores ganan el rol en el mismo
// evento con un único compiler sirviendo; todos fetchean
// concurrentemente y las tres copias en disco son idénticas a los bytes
// anclados del Owner (el camino para el que existe la caché de serving).
async fn test_fetch_burst_concurrent_evaluators_single_server() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();
    let node4_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let mut extra_nodes = Vec::new();
    for contracts in [
        &node2_contracts,
        &node3_contracts,
        &node4_contracts,
    ] {
        let (node, _dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers: vec![RoutingNode {
                peer_id: node1.api.peer_id().to_string(),
                address: vec![node1.listen_address.clone()],
            }],
            always_accept: true,
            contracts_path: Some(contracts.path().to_path_buf()),
            ..Default::default()
        })
        .await;
        node_running(&node.api).await.unwrap();
        extra_nodes.push((node, _dirs));
    }

    let node2 = &extra_nodes[0].0;
    let node3 = &extra_nodes[1].0;
    let node4 = &extra_nodes[2].0;

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api, &node4.api],
    )
    .await;

    // SN 1: schema Example v1; los tres nodos ganan evaluator+witness en
    // el mismo evento → los tres fetchean a la vez del único compiler.
    let evaluator_entries = |names: &[&str]| {
        names
            .iter()
            .map(|name| json!({"name": name, "namespace": []}))
            .collect::<Vec<_>>()
    };

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                },
                {
                    "name": "AveNode4",
                    "key": node4.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": evaluator_entries(&["Owner", "AveNode2", "AveNode3", "AveNode4"]),
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": evaluator_entries(&["Owner", "AveNode2", "AveNode3", "AveNode4"]),
                        "creator": [{"name": "Owner", "namespace": [], "quantity": 10}],
                        "issuer": [{"name": "Owner", "namespace": []}]
                    }
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    for node in [node2, node3, node4] {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    let artifact_name = format!("{governance_id}_Example");
    let anchored = fs::read(
        node1_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .join("contract.wasm"),
    )
    .unwrap();

    for (name, contracts) in [
        ("AveNode2", &node2_contracts),
        ("AveNode3", &node3_contracts),
        ("AveNode4", &node4_contracts),
    ] {
        let bytes = wait_artifact_bytes(contracts.path(), &artifact_name).await;
        assert_eq!(
            bytes, anchored,
            "la copia fetcheada de {name} es idéntica a los bytes anclados"
        );
    }

    // Y los cuatro evalúan: un fact commitea (quórum Majority de 4).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModTwo": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 3, "three": 0}));

    for (node, _) in &extra_nodes {
        node_running(&node.api).await.unwrap();
    }
}
#[test(tokio::test)]
// TEST-061 (alcance determinista): un nodo recién reiniciado, con la
// recuperación de arranque completada (artefacto intacto verificado
// contra el ancla), SIRVE en plan B de inmediato. La ventana "bloqueado
// durante la recuperación" no es observable sin hooks de timing; aquí se
// pincha que la recuperación no deja el serving bloqueado para siempre.
async fn test_serving_after_boot_recovery_intact_artifact() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    node3
        .api
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::Many(vec![
                PublicKey::from_str(node1.api.public_key()).unwrap(),
                PublicKey::from_str(&node2.api.public_key()).unwrap(),
            ]),
        )
        .await
        .unwrap();

    // SN 1: schema Example v1; AveNode2 evaluador y testigo del gov.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"]
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
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // Reinicio de AveNode2: recuperación de arranque con el artefacto
    // intacto (verificado contra el ancla, sin refetch).
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node2_v1)
        .await;

    // SN 2: AveNode3 gana el rol de evaluador. El Owner no puede servir
    // (directorio movido): el fetch de AveNode3 va al plan B — AveNode2,
    // recién reiniciado, debe servir desde el primer momento.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "AveNode3",
                                "namespace": []
                            }
                        ]
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(
        node3_v1, node2_v1,
        "AveNode2 sirvió en plan B inmediatamente tras su recuperación de arranque"
    );

    fs::rename(&node1_hidden, &node1_dir).unwrap();
    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-062: gate NodeBehind — un evaluador que nunca sincroniza la v2
// (gov atrasada, artefacto v1) responde NotServed a un probe con la
// gov_version nueva: el fetcher no descarga bytes que sabe obsoletos y
// el fetch queda estancado hasta que el Owner (al día) puede servir.
async fn test_fetch_failover_from_outdated_server() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    // Ni AveNode2 ni AveNode3 son testigos del gov en los roles: solo
    // sincronizan por update_subject manual (control de versiones).
    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api, &node3.api])
            .await;

    // SN 1: schema Example v1; ambos evaluadores fetchean la v1.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    for node in [&node2, &node3] {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;

    // SN 2: cambio de contrato a la v2; el Owner compila y commitea.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El Owner queda sin poder servir la v2.
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_v2 = fs::read(node1_dir.join("contract.wasm")).unwrap();
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // AveNode2 NUNCA sincroniza la v2: queda atrasado con la v1.
    // AveNode3 aplica SN 2: descarta la v1 y arranca el fetch de la v2.
    // Plan A (Owner) no sirve; plan B solo tiene a AveNode2, atrasado →
    // NotServed (NodeBehind): nadie sirve bytes obsoletos.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "el servidor atrasado no sirve la v1 como si fuera la v2"
    );

    // El Owner vuelve a poder servir: el fetch completa con la v2.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // AveNode2 sigue atrasado con sus bytes v1 intactos.
    let node2_still_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(node2_still_v1, node2_v1);
    assert_ne!(node2_still_v1, node1_v2);

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-063: cambio solo de init_value (mismo contrato) en la vía FETCH:
// el ancla no se mueve (mismo hash de wasm), el evaluador que fetcheada
// NO re-fetchea — el chequeo de init re-corre contra sus bytes locales —
// y sigue evaluando aunque el servidor no pueda servir nada.
async fn test_fetch_init_only_change_no_refetch() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador (fetchea la v1).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                            },
                            {
                                "name": "AveNode2",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: cambio solo de init_value (mismo contrato). Commitea en el
    // Owner ANTES de ocultar su artefacto.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_initial_value": {
                        "one": 1,
                        "two": 2,
                        "three": 3
                    }
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El Owner no puede servir NADA: si AveNode2 intentara re-fetchear se
    // estancaría. Aplica SN 2 con la red de artefactos inútil.
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Sin refetch posible: los bytes no cambian y el nodo sigue evaluando
    // (el fact commitea con su voto, Majority de 2).
    let node2_after =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(
        node2_after, node2_v1,
        "el cambio init-only no re-fetchea: los bytes no se mueven"
    );

    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 5}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    // El tracker se creó DESPUÉS del cambio de init_value: su estado
    // inicial es el nuevo {one: 1, two: 2, three: 3}.
    assert_eq!(state.properties, json!({"one": 5, "two": 2, "three": 3}));

    fs::rename(&node1_hidden, &node1_dir).unwrap();
    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-064: el requester reinicia con una request de compilación en
// vuelo (compilada, atascada en validación por quórum con el segundo
// validador caído). El request manager persiste la request y la reanuda
// en el arranque (request/mod.rs): sigue atascada mientras el validador
// falta y commitea cuando vuelve — la request no se pierde ni reinicia
// la compilación.
async fn test_requester_reboot_resumes_inflight_compile_request() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: AveNode2 entra como validador y testigo de la gobernanza
    // (quórum de validación Majority de {Owner, AveNode2} = 2).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2"],
                    "validator": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // AveNode2 cae: la validación del siguiente evento no alcanza quórum.
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    // SN 2: alta del schema Example con contrato — compila, evalúa y
    // aprueba (auto), pero la validación queda atascada.
    let json = json!({
        "roles": {
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    let state = get_subject(&node1.api, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(
        governance_properties(state.properties).version,
        1,
        "la request compilada queda atascada en validación sin quórum"
    );

    // Reinicio del requester: la request se reanuda desde el estado
    // persistido (sigue atascada: el validador sigue caído).
    let (mut node1, _node1_dirs) = (node1, _node1_dirs);
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    let state = get_subject(&node1.api, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(
        governance_properties(state.properties).version,
        1,
        "la request reanudada sigue esperando quórum de validación"
    );

    // El validador vuelve: la request reanudada commitea.
    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El artefacto compilado antes del reinicio se promociona al commit.
    let artifact_name = format!("{governance_id}_Example");
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "el commit tras el reinicio promociona el artefacto compilado"
    );

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-004: el requester desactualizado recibe Outdated del servidor,
// resincroniza la gobernanza por su cuenta y reintenta hasta obtener el
// artefacto NUEVO — nunca se cuelga ni pierde la request. AveNode2 se
// queda en SN1 (ancla v1, artefacto borrado) y reinicia: su recovery de
// arranque sondea a AveNode1 (ya en SN2) con gov_version=1 → Outdated →
// TriggerGovUpdate → resincroniza a SN2 → retarget al ancla v2 → fetch
// completa con los bytes de la v2.
async fn test_fetch_outdated_requester_resyncs_and_completes() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let _node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: cambio de contrato a la v2. AveNode1 aplica; AveNode2 NO
    // (se queda en SN1 con la ancla v1).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_v2 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // AveNode2 pierde su artefacto v1 y REINICIA sin haber aplicado SN2:
    // la recovery de arranque (ancla v1, artefacto ausente) sondea a
    // AveNode1 con gov_version=1 → Outdated → resincroniza a SN2 y
    // fetchea la v2. (El reboot es el trigger: en caliente el reconcile
    // con el contrato sin cambios no re-chequea el disco.)
    fs::remove_dir_all(
        node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name),
    )
    .unwrap();

    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    // El Outdated empuja a AveNode2 a resincronizar: acaba en SN2.
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Y el fetch retargeteado trae los bytes de la v2 (ancla nueva).
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // Ambos evaluadores (quorum Majority = 2 de 2) votan con el módulo
    // v2: un fact que la v1 rechazaría (ModThree=50) commitea.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-065: staging manipulado antes del commit. Con aprobación manual
// se corrompen los bytes del staging tras la compilación; el check de
// promoción (gov/mod.rs) es sobre metadatos (registrados al compilar),
// así que los bytes tocados se promocionan — pero la verificación de
// carga (compilation/support.rs) re-hashea el wasm persistido contra
// los metadatos/ancla, detecta el mismatch y recompila anclado: el nodo
// sana solo en el primer uso. Mientras tanto los fetchers rechazan los
// bytes malos por hash y reintentan hasta el artefacto sano.
async fn test_staging_tampered_pre_commit_heals_after_promotion() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    // always_accept por defecto (false) en AveNode1: aprobación manual.
    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1 (pendiente de aprobación): schema Example v1; AveNode2
    // evaluador.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        &node1.api,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    // El staging existe en la RAÍZ de contracts_path (la compilación ya
    // ocurrió); se corrompen los bytes del wasm staged.
    let staging_prefix = format!("{governance_id}_temp_staging_Example_");
    let mut staging_dir = None;
    for _ in 0..100 {
        if let Ok(entries) = fs::read_dir(node1_contracts.path()) {
            staging_dir = entries.filter_map(|e| e.ok()).find_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with(&staging_prefix).then(|| e.path())
            });
            if staging_dir.is_some() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let staging_dir =
        staging_dir.expect("el staging de Example debe existir pre-commit");

    let tampered: &[u8] = b"tampered staging bytes, hash mismatch";
    fs::write(staging_dir.join("contract.wasm"), tampered).unwrap();

    // Aprobado: el commit promociona (rename) el staging — el check de
    // metadatos cuadra (se registró al compilar, antes del tampering).
    emit_approve(
        &node1.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    assert!(
        node1_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "la promoción copia el staging al artefacto oficial"
    );

    // AveNode2 sincroniza e intenta fetchear: si recibe los bytes
    // corruptos los rechaza por hash (no cuadran con el ancla) y
    // reintenta.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Primer uso del contrato en AveNode1: la verificación de carga
    // detecta el mismatch (wasm persistido ≠ metadatos/ancla) y
    // recompila anclado → bytes sanos re-persistidos.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 5}}),
        true,
    )
    .await
    .unwrap();

    // El quorum (Majority de {Owner, AveNode2} = 2) exige el voto de
    // AveNode2: el fact solo commitea si AveNode2 fetcheó el artefacto
    // SANO (tras la curación de AveNode1) y evaluó con él.
    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 5, "two": 0, "three": 0}));

    // El artefacto oficial de AveNode1 ya no son los bytes manipulados.
    let healed =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    assert_ne!(
        healed, tampered,
        "la verificación de carga reemplazó los bytes manipulados"
    );
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &healed)
        .await;

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-066: cambio de contrato con el fetch de la versión anterior en
// vuelo. AveNode2 está ciclando el fetch de la v1 (AveNode1 no puede
// servirla) cuando SN2 cambia el contrato: el reconcile retargeta el
// fetch al ancla v2 y completa — nunca se cuelga esperando la v1
// inservible.
async fn test_contract_change_retargets_inflight_fetch() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // AveNode1 no puede servir la v1: el fetch de AveNode2 cicla en
    // NotServed (queda "en vuelo").
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "el fetch de la v1 sigue en vuelo (AveNode1 no la sirve)"
    );

    // SN 2: cambio de contrato a la v2. AveNode1 compila la v2 (escribe
    // un dir oficial nuevo; el oculto con la v1 nunca vuelve).
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": EXAMPLE_CONTRACT_V2
            }]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let node1_v2 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    assert_ne!(node1_v1, node1_v2);

    // AveNode2 aplica SN2: el reconcile retargeta el fetch en vuelo de
    // la v1 a la v2 → completa con los bytes nuevos.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // Comportamiento v2 confirmado: ModThree=50 commitea con el voto de
    // ambos evaluadores.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-067: el fetcher reinicia a mitad de un ciclo de fetch (el
// servidor aún no puede servir): la recovery de arranque re-arma el
// fetch desde el ancla persistida y, cuando el servidor vuelve a poder
// servir, completa con los bytes correctos.
async fn test_fetcher_reboot_mid_fetch_cycle_recovers() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example v1; AveNode2 evaluador.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "Owner",
                                "namespace": []
                            },
                            {
                                "name": "AveNode2",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // AveNode1 no puede servir: el fetch de AveNode2 cicla en NotServed.
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "AveNode2 está a mitad de un ciclo de fetch estancado"
    );

    // AveNode2 reinicia a mitad del ciclo: la recovery de arranque
    // re-arma el fetch desde el ancla persistida (sigue sin completar:
    // AveNode1 sigue sin servir).
    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !node2_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "tras el reboot el fetch sigue estancado mientras AveNode1 no sirve"
    );

    // AveNode1 vuelve a poder servir: el fetch re-armado completa con
    // los bytes de la v1.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(node2_v1, node1_v1);

    // Y evalúa con el módulo recuperado (quorum Majority = 2 de 2).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-068: failover de plan B con mismatch de hash. El único servidor
// de plan B (AveNode2) sirve un artefacto corrupto: el requester
// (AveNode3) verifica el hash contra el ancla, rechaza la transferencia
// sin persistir nada y reintenta en el siguiente ciclo; cuando AveNode2
// vuelve a servir bytes sanos (tras reiniciar, lo que también vacía su
// caché de serving), el fetch completa. El evento ajeno de SN 2 vacía
// la caché de serving del Owner (ServingBlocked durante el apply), que
// el fetch de AveNode2 había calentado con los bytes sanos: sin él, el
// Owner seguiría sirviendo la v1 desde caché con el directorio oculto.
async fn test_plan_b_corrupt_transfer_rejected_then_retry_succeeds() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        always_accept: true,
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api, &node3.api])
            .await;

    // SN 1: schema Example v1. Evaluadores: AveNode2 y AveNode3 (Owner
    // NO es evaluador de schema → el plan B de AveNode3 es exactamente
    // {AveNode2}; el plan A es {AveNode1} como compiler de gobernanza).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.api.public_key()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            {
                                "name": "AveNode2",
                                "namespace": []
                            },
                            {
                                "name": "AveNode3",
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
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // AveNode2 fetchea la v1 sana.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node2_v1 =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // SN 2: evento ajeno al contrato (alta de miembro sin roles). El
    // fetch de AveNode2 calentó la caché de serving del Owner con los
    // bytes sanos (TTL 300s, SERVING_CACHE_TTL); aplicar este evento
    // bloquea el serving durante el apply y la vacía — sin esto, el
    // Owner seguiría sirviendo la v1 desde caché con el directorio
    // oculto y AveNode3 persistiría bytes sanos.
    let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode4",
                    "key": key
                }
            ]
        }
    });
    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // AveNode2 aplica SN 2: si se quedara en SN 1 su gate de serving
    // respondería NotServed a los probes de AveNode3 (servidor atrasado,
    // patrón TEST-062). El contrato no cambia: conserva el artefacto
    // sin refetch (skip guard).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Se corrompe el artefacto que AveNode2 servirá (guardando el
    // original para restaurarlo después).
    let node2_wasm = node2_contracts
        .path()
        .join("contracts")
        .join(&artifact_name)
        .join("contract.wasm");
    fs::write(&node2_wasm, b"corrupted served artifact bytes").unwrap();

    // El plan A (AveNode1) no puede servir: caché vacía (SN 2) y
    // directorio oculto → serve None, sin rellenar la caché.
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // AveNode3 sincroniza e inicia el fetch: plan A NotServed, plan B
    // sirve bytes corruptos → el hash no cuadra con el ancla → rechaza
    // sin persistir y reintenta (probes+transferencia son instantáneos
    // en memoria y el timeoff base es 1s: en 3s hay ≥1 ciclo fallido
    // completo).
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name)
            .exists(),
        "las transferencias corruptas se rechazan: nada persiste"
    );

    // AveNode2 reinicia (vacía su caché de serving, que retiene los
    // bytes corruptos 300s) con el artefacto restaurado en disco.
    fs::write(&node2_wasm, &node2_v1).unwrap();

    let (mut node2, _node2_dirs) = (node2, _node2_dirs);
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(node2.keys.clone()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    // El siguiente ciclo de AveNode3 obtiene los bytes sanos.
    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(node3_v1, node2_v1);

    // Ambos evaluadores (Majority de 2 = 2) votan el fact con el módulo
    // recuperado.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 9}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 9, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}
#[test(tokio::test)]
// TEST-069: alta de schema con todos los pools de compilación caídos:
// el compiler responde Unavailable, la request se aparca
// (Reboot/RebootTimeOut) en vez de colgar la gobernanza, que no avanza
// de versión; al reiniciar con un pool vivo la request aparcada
// reintenta, compila y commitea.
async fn test_schema_add_with_dead_pool_parks_and_recovers() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();

    // Pool muerto desde el arranque (los endpoints explícitos ganan al
    // compilador embebido de test).
    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    // La creación de la gobernanza no necesita compilación.
    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1 (intento): alta del schema Example con contrato → el
    // compiler no puede compilar con el pool muerto.
    let json = json!({
        "roles": {
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // La request se aparca (Reboot/RebootTimeOut): ni commitea ni
    // aborta la gobernanza.
    let mut parked = false;
    for _ in 0..200 {
        if let Ok(state) =
            node1.api.get_request_state(request_id.clone()).await
            && matches!(
                state.state,
                RequestState::Reboot | RequestState::RebootTimeOut { .. }
            )
        {
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        parked,
        "con el pool muerto la request se aparca (Reboot/RebootTimeOut)"
    );

    // La gobernanza no avanza de versión.
    let state = get_subject(&node1.api, governance_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(governance_properties(state.properties).version, 0);

    // Reinicio con pool vivo (endpoints vacíos → compilador embebido de
    // test): la request aparcada reintenta, compila y commitea.
    let (mut node1, _node1_dirs) = (node1, _node1_dirs);
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // El schema queda operativo: un tracker evalúa con el contrato.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 3, "two": 0, "three": 0}));
}
#[test(tokio::test)]
// TEST-070: boot recovery FATAL con pool muerto. Un compiler con el
// artefacto oficial ausente que no puede recompilar (pool caído) NO
// arranca: crash-fast en bootstrap (`Api::build` error) en vez de un
// nodo zombi sin artefacto. Con el pool vivo arranca, recompila anclado
// (mismos bytes) y queda operativo.
async fn test_boot_fatal_dead_pool_then_recovers_with_live_pool() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();

    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // SN 1: schema Example v1 (Owner compiler y evaluador).
    let json = json!({
        "roles": {
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
                                "name": "Owner",
                                "namespace": []
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": 10
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
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // Apagado limpio y borrado del artefacto oficial.
    let (mut node1, _node1_dirs) = (node1, _node1_dirs);
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    fs::remove_dir_all(
        node1_contracts
            .path()
            .join("contracts")
            .join(&artifact_name),
    )
    .unwrap();

    // Boot con pool muerto: la recovery del artefacto es bloqueante y
    // sin pool no puede recompilar → el nodo NO arranca (crash-fast).
    let dead_boot = try_create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![],
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .await;
    assert!(
        dead_boot.is_err(),
        "boot fatal: compiler sin artefacto ni pool no arranca"
    );

    // Boot con pool vivo (compilador embebido): arranca, recompila
    // anclado (bytes idénticos — compilación determinista) y opera.
    let (node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![],
        keys: Some(node1.keys.clone()),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let healed =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    assert_eq!(
        healed, node1_v1,
        "la recompilación anclada reproduce los bytes originales"
    );

    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 4}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 4, "two": 0, "three": 0}));
}
