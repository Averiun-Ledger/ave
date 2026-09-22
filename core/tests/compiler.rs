//! End-to-end tests of the level-3 compilation flow: compile quorum
//! and evidence, artifact staging/promotion/sweeps, corruption and
//! recovery, dead-pool behavior and the artifact fetch/serving protocol
//! (plan A compilers, plan B evaluators). All of it drives real
//! governance events through real nodes — the tests live apart from
//! `gov.rs` because that file pins governance flows (approvals, roles,
//! schema CRUD, viewpoints), not the compiler machinery.
//!
//! Requires the `test` feature: dead-pool tests inject compiler
//! endpoints, a config surface that only exists in test builds
//! (production nodes compile in-process).
#![cfg(feature = "test")]

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    str::FromStr,
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ave_common::{
    SchemaType,
    bridge::{
        request::ApprovalStateRes,
        response::{EvalResDB, RequestEventDB},
    },
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, hash_borsh,
        keys::{Ed25519Signer, KeyPair},
    },
    response::RequestState,
};
use ave_core::auth::AuthWitness;
use ave_core::Api;
use ave_core::compilation::artifact::{ArtifactFetchResult, ArtifactProbeResult};
use ave_core::compilation::contract_compiler::FetchObs;
use ave_core::config::{CompilerNodeConfig, GovernanceSyncConfig};
use ave_core::governance::data::GovernanceData;
use ave_core::governance::model::{
    PolicyGov, Quorum, RoleGovIssuer, RolesGov, RolesTrackerSchemas,
};
use ave_core::helpers::network::test_faults::{
    FaultAction, FaultDirection, FaultMessage, FaultRule,
};
use ave_core::helpers::network::{ActorMessage, NetworkMessage};
use ave_core::test_compiler::{ScriptedCompiler, ScriptedTransform};

use ave_network::{ComunicateInfo, NodeType, RoutingNode};
use base64::{Engine as _, prelude::BASE64_STANDARD};
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
// Espera ACOTADA al estado de una request: los helpers comunes son
// bucles sin límite y una regresión de liveness se escondería como un
// cuelgue infinito bajo carga; el test debe FALLAR mostrando el estado
// en el que la request quedó atascada.
async fn wait_request_state_bounded(
    api: &Api,
    request_id: DigestIdentifier,
    attempts: u32,
    want: &dyn Fn(&RequestState) -> bool,
    what: &str,
) -> RequestState {
    let mut last = None;
    for _ in 0..attempts {
        if let Ok(state) = api.get_request_state(request_id.clone()).await {
            if want(&state.state) {
                return state.state;
            }
            last = Some(state.state);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!(
        "timeout waiting for request {request_id} to reach {what}; last state: {last:?}"
    );
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

    wait_request_state_bounded(
        &node1.api,
        request_id,
        100,
        &|state| matches!(state, RequestState::Abort { .. }),
        "Abort",
    )
    .await;

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

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // El quórum de compile puede necesitar ciclos de reboot bajo carga
    // (cada RebootTimeOut espera el schedule): acotado pero generoso.
    wait_request_state_bounded(
        &node1.api,
        request_id,
        400,
        &|state| matches!(state, RequestState::Finish),
        "Finish",
    )
    .await;

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

    // Compile and evaluation do complete: the staging is written to
    // disk and the approval stays pending inside the validation phase.
    // The request must not be awaited to a terminal state: with the
    // approval unreachable it would abort on its own once the approval
    // deadline lapses, and the sweep would already have run.
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

    let request_id = emit_fact(&node1.api, governance_id.clone(), json, false)
        .await
        .unwrap();

    // Wait until the staging dir exists on disk (polling, like the
    // helpers).
    for _ in 0..100 {
        if !staging_dirs().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(staging_dirs().len(), 1);

    // Manual abort with the approval still pending and the staging
    // already written: the sweep applies as well.
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
// TEST-068: failover de plan B con artefacto corrupto. El disco del
// único servidor de plan B (AveNode2) está corrompido: al intentar
// servirlo detecta su propia corrupción (re-hash contra la metadata del
// register), descarta el artefacto y no sirve nada mientras se
// auto-cura (HealArtifact → fetch); el requester (AveNode3) agota
// ciclos sin persistir nada. Al restaurar el plan A (Owner), el heal de
// AveNode2 y el fetch de AveNode3 completan con los bytes sanos
// anclados. El evento ajeno de SN 2 vacía la caché de serving del Owner
// (ServingBlocked durante el apply), que el fetch de AveNode2 había
// calentado con los bytes sanos: sin él, el Owner seguiría sirviendo la
// v1 desde caché con el directorio oculto.
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

    // Se corrompe el artefacto en disco de AveNode2 (guardando el
    // original para las comparaciones): al servirlo detectará el
    // mismatch, lo descartará (disco y register) y no servirá nada.
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

    // AveNode3 sincroniza e inicia el fetch: plan A NotServed y plan B
    // tampoco sirve (descarte pre-serve) → no persiste nada y reintenta
    // (probes+transferencia son instantáneos en memoria y el timeoff
    // base es 1s: en 3s hay ≥1 ciclo fallido completo).
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

    // Recuperación: el Owner vuelve a servir (se deshace el ocultado).
    // El descarte pre-serve borró el artefacto de AveNode2 del disco y
    // del register, así que no hay nada que restaurar a mano: su heal
    // (HealArtifact → fetch, ciclo que nunca abandona) completa en
    // cuanto el plan A responde, y el fetch de AveNode3 también.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    let node2_healed =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    let node3_v1 =
        wait_artifact_bytes(node3_contracts.path(), &artifact_name).await;
    assert_eq!(node2_healed, node2_v1);
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

// Espera acotada a que la observabilidad del fetch de un contrato
// (`test_fetch_obs`) cumpla la condición: los tests leen la máquina de
// estados del fetch por aquí en vez de correr carreras con timers o
// rastrear logs.
async fn wait_fetch_obs(
    node: &ave_core::Api,
    contract_name: &str,
    cond: impl Fn(&FetchObs) -> bool,
) -> FetchObs {
    for _ in 0..100 {
        if let Some(obs) = node.test_fetch_obs(contract_name).await
            && cond(&obs)
        {
            return obs;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("timeout waiting for fetch obs of {contract_name}");
}

#[test(tokio::test)]
// TEST-044: respuesta `Busy` al `ArtifactReq` tras un `CanServe`
// (semántica busy mid-fetch ratificada el 2026-09-10): el peer que ganó
// el probe empezó a compilar a mitad del fetch → el fetcher hace
// failover-first al siguiente candidato `CanServe` Y conserva al peer
// ocupado en `round.busy` (se re-sondea después, NO se quema).
// Escenario determinista con los hooks de fault-injection:
// - Hold inbound de la `ArtifactProbeRes` del Owner (B) en AveNode3 →
//   AveNode2 (A) gana el probe (primer `CanServe`).
// - Hold outbound de la `ArtifactRes` real de A → el fetcher no recibe
//   los bytes de A; el `Busy` se inyecta inbound en AveNode3 como si
//   viniera de A (los mensajes de artefacto no van firmados: el
//   intermediario los entrega al ContractCompiler con el sender de la
//   clave indicada). Nonces: el probe round es el nonce 0 y el primer
//   `ArtifactReq` el nonce 1 — primera y única ronda del fetch.
// - Hold outbound de la `ArtifactRes` de B → el failover a B expira por
//   timeout (5s). Como A sigue en `busy` (no quemado), se le re-sondea
//   (probes_sent 2 → 3) y el fetch completa desde A sin agotar el ciclo.
//   Si A se quemara, el ciclo se agotaría: no hay plan B (el único
//   evaluador del schema es el propio AveNode3).
async fn test_fetch_busy_mid_fetch_failover_preserves_busy_peer() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();
    let node2_pk = PublicKey::from_str(node2.api.public_key()).unwrap();
    let node3_pk = PublicKey::from_str(node3.api.public_key()).unwrap();

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

    // SN 2: alta del schema Example (contrato v1). Los compilers son
    // Owner y AveNode2: ambos compilan la v1 localmente. AveNode3 es el
    // ÚNICO evaluador del schema: solo obtiene el artefacto por fetch y
    // no tiene plan B (evaluators menos uno mismo = conjunto vacío).
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

    // Ambos compilers tienen la v1 promocionada antes de que AveNode3
    // sondee (su gate de serving exige el artefacto registrado).
    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // AveNode3: retiene la respuesta de probe del Owner → AveNode2 (A)
    // gana el probe.
    node3
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    // AveNode2 (A): retiene su respuesta de artefacto real; el `Busy`
    // lo inyecta el test.
    node2
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: Some(node3_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    // Owner (B): retiene su respuesta de artefacto → el failover a B
    // expira por timeout.
    node1
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: Some(node3_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // AveNode3 aplica SN 2: arranca el fetch de la v1 (probe round nonce
    // 0 a ambos compilers).
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // A ganó el probe y el `ArtifactReq` ya salió (nonce 1).
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.downloads_started == 1 && obs.phase == Some("fetch")
    })
    .await;
    assert_eq!(obs.probes_sent, 2);

    // La respuesta retenida del Owner llega tarde: entra en `can_serve`
    // como candidato de failover.
    assert_eq!(node3.api.test_release_held().await.unwrap(), 1);

    // A responde `Busy` al `ArtifactReq` (empezó a compilar mid-fetch):
    // failover-first a B y A se conserva en `busy`.
    node3
        .api
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver: node3_pk.clone(),
                    receiver_actor: format!(
                        "/user/node/subject_manager/{governance_id}/Example_contract_compiler"
                    ),
                },
                message: ActorMessage::ArtifactRes {
                    request_nonce: 1,
                    result: ArtifactFetchResult::Busy,
                },
            },
            &node2_pk,
        )
        .await
        .unwrap();

    // Failover a B: su respuesta retenida hará expirar el intento.
    wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.downloads_started == 2 && obs.phase == Some("fetch")
    })
    .await;

    // Tras el timeout de B, A — conservado en `busy`, no quemado — se
    // re-sondea y sirve los bytes: el fetch completa sin agotar ciclo.
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.downloads_started, 3);
    assert_eq!(obs.probes_sent, 3);
    assert_eq!(obs.cycles_exhausted, 0);

    // Los bytes registrados son los anclados (idénticos a los del Owner)
    // y AveNode3 evalúa con ellos: un fact commitea con su voto.
    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;

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
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node3.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-042 (pin de BUG-012): un peer corrupto (AveNode2, A) sirve bytes
// que no casan con el ancla → el receptor los descarta y A se quema vía
// `attempt_failed` (`round.failed`); un `CanServe` duplicado TARDÍO de A
// (el nonce del probe round, inyectado tras el burn) NO lo readmite como
// candidato de failover en el mismo ciclo: cuando el peer honesto
// (Owner, B) también falla (respuesta retenida → timeout), el ciclo se
// agota SIN una tercera descarga desde A. Con BUG-012 sin fijar, A se
// readmitiría y completaría el fetch (su corrupción es de una sola
// ocurrencia). En el ciclo siguiente — round nuevo, `failed` limpio por
// diseño ("never gives up") — el fetch completa con los bytes anclados;
// cuál de los dos sirve es indistinto (ambos sirven ya bytes válidos),
// el pin es la no-readmisión en el MISMO ciclo. No hay plan B: el único
// evaluador del schema es el propio AveNode3.
async fn test_fetch_late_duplicate_can_serve_does_not_readmit_burned_peer() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();
    let node2_pk = PublicKey::from_str(node2.api.public_key()).unwrap();
    let node3_pk = PublicKey::from_str(node3.api.public_key()).unwrap();

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

    // SN 2: alta del schema Example (contrato v1), como en TEST-044.
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

    // Ambos compilers tienen la v1 promocionada antes del fetch.
    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // AveNode3: retiene la respuesta de probe del Owner → AveNode2 (A)
    // gana el probe.
    node3
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    // AveNode2 (A): su primera respuesta de artefacto sale con el wasm
    // corrupto (zstd válido, hash distinto del ancla) → el receptor lo
    // descarta y quema a A.
    node2
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: Some(node3_pk.clone()),
            remaining: Some(1),
            action: FaultAction::CorruptWasm,
        })
        .await
        .unwrap();
    // Owner (B): retiene su respuesta de artefacto → el failover a B
    // expira por timeout.
    node1
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: Some(node3_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // AveNode3 aplica SN 2: arranca el fetch de la v1 (probe round nonce
    // 0 a ambos compilers).
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // A ganó el probe: primer intento de descarga en vuelo.
    wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.downloads_started == 1
    })
    .await;

    // La respuesta retenida del Owner se entrega: entra en `can_serve`
    // (o cierra el round reanudado si el burn de A ya ocurrió — ambos
    // caminos llevan al failover a B).
    assert_eq!(node3.api.test_release_held().await.unwrap(), 1);

    // A sirvió bytes corruptos → descarte + burn → failover a B (su
    // respuesta retenida mantiene el intento vivo 5s).
    wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.downloads_started == 2 && obs.phase == Some("fetch")
    })
    .await;

    // `CanServe` duplicado tardío de A (nonce del probe round): A está
    // en `round.failed` y NO debe readmitirse como candidato.
    node3
        .api
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver: node3_pk.clone(),
                    receiver_actor: format!(
                        "/user/node/subject_manager/{governance_id}/Example_contract_compiler"
                    ),
                },
                message: ActorMessage::ArtifactProbeRes {
                    request_nonce: 0,
                    result: ArtifactProbeResult::CanServe,
                },
            },
            &node2_pk,
        )
        .await
        .unwrap();

    // B expira y se quema: sin readmisión no quedan candidatos → ciclo
    // agotado con exactamente 2 descargas (ni una más desde A).
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.cycles_exhausted == 1
    })
    .await;
    assert_eq!(obs.downloads_started, 2);

    // Ciclo siguiente (timeoff ~1s): round nuevo; ambos sirven ya bytes
    // válidos → el fetch completa con una sola descarga más.
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.downloads_started, 3);
    assert_eq!(obs.probes_sent, 4);
    assert_eq!(obs.cycles_exhausted, 1);

    // Los bytes registrados son los anclados y AveNode3 evalúa con
    // ellos: un fact commitea con su voto.
    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;

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

// Espera acotada a que el contador de builds del scripted compiler
// alcance `expected` (los tests lo leen en vez de correr carreras con
// timers o rastrear logs).
async fn wait_compiles_received(scripted: &ScriptedCompiler, expected: u64) {
    for _ in 0..100 {
        if scripted.compiles_received() >= expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!(
        "timeout waiting for {expected} compiles received, actual {}",
        scripted.compiles_received()
    );
}

// Volcado del log de compiles del scripted compiler con los sources
// conocidos etiquetados: diagnóstico para los pins de "exactamente un
// build" de la adquisición diferida cuando fallan bajo carga.
fn scripted_compile_log(scripted: &ScriptedCompiler) -> String {
    let labels: [(&str, &str); 3] = [
        ("v1", EXAMPLE_CONTRACT),
        ("v2", EXAMPLE_CONTRACT_V2),
        ("v3", FUEL_EXHAUSTING_CONTRACT),
    ];
    scripted
        .compiles_log()
        .iter()
        .map(|(elapsed, source_hash)| {
            let label = labels
                .iter()
                .find(|(_, source)| {
                    hash_borsh(
                        &*HashAlgorithm::Blake3.hasher(),
                        &source.to_string(),
                    )
                    .is_ok_and(|hash| hash.to_string() == *source_hash)
                })
                .map_or("unknown", |(name, _)| name);
            format!("+{elapsed:?} {label}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// Variante única por ejecución de un contrato de prueba. La caché
// global de builds (/tmp/ave-contract-artifacts) se comparte entre
// tests y persiste entre ejecuciones: un hit serviría el artefacto
// compilado sin llamar al scripted compiler, y ni `compiles_received`
// ni el hold se enterarían del build. Un comentario con nonce cambia
// el hash de la fuente (la clave de la caché) sin alterar el contrato.
fn unique_contract(base64_source: &str) -> String {
    let source = BASE64_STANDARD.decode(base64_source).unwrap();
    let source = String::from_utf8(source).unwrap();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    BASE64_STANDARD.encode(format!("{source}\n// test nonce: {nonce}"))
}

// Variante comprimida de un contrato de prueba: base64(zstd(fuente)).
// La descompresión es transparente al consenso (cada nodo decodifica el
// payload antes de compilar), así que el artefacto resultante debe ser
// byte a byte idéntico al de la misma fuente en plano.
fn compressed_contract(base64_source: &str) -> String {
    let source = BASE64_STANDARD.decode(base64_source).unwrap();
    BASE64_STANDARD.encode(zstd::bulk::compress(&source, 3).unwrap())
}

// Espera acotada a que la residencia del módulo de un contrato en
// memoria (`test_has_contract_module`, el helper `contracts`) alcance el
// estado esperado.
async fn wait_module_resident(
    node: &ave_core::Api,
    contract_name: &str,
    expected: bool,
) {
    for _ in 0..100 {
        if node.test_has_contract_module(contract_name).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!(
        "timeout waiting for module residency {expected} of {contract_name}"
    );
}

// Espera acotada a que el nodo deje de responder (sistema caído, p.ej.
// tras un crash-fast de la recuperación de artefactos). El ask se acota
// con un timeout: un sistema caído puede no contestar nunca.
async fn wait_node_down(node: &ave_core::Api) {
    for _ in 0..100 {
        let down = match tokio::time::timeout(
            Duration::from_secs(2),
            node.get_network_state(),
        )
        .await
        {
            Ok(Ok(_)) => false,
            Ok(Err(_)) | Err(_) => true,
        };
        if down {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("timeout waiting for the node to go down");
}

// Si el directorio del artefacto oficial de un contrato existe en disco.
fn artifact_dir_exists(
    contracts_path: &std::path::Path,
    artifact_name: &str,
) -> bool {
    contracts_path.join("contracts").join(artifact_name).exists()
}

// Borra de la base de datos local del nodo (con el nodo APAGADO) las
// filas del ContractRegister de una gobernanza: las anclas de
// compilación y la metadata de artefactos que persiste son una
// proyección reconstruible del ledger, así que el arranque debe
// re-derivarlas. Las tablas son compartidas por todos los registers del
// nodo y las filas de cada gobernanza se distinguen por `prefix` (el
// identificador de la gobernanza). Los valores van en claro (el store
// del register no cifra), así que basta una sqlite estándar.
fn wipe_contract_register_tables(db_path: &std::path::Path, gov_id: &str) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let mut wiped = 0usize;
    for table in [
        "contract_register_events",
        "contract_register_states",
        "contract_register_metadata",
    ] {
        wiped += conn
            .execute(
                &format!("DELETE FROM {table} WHERE prefix = ?1"),
                rusqlite::params![gov_id],
            )
            .unwrap();
    }
    assert!(
        wiped > 0,
        "el register debía tener filas persistidas antes del borrado"
    );
}

#[test(tokio::test)]
// TEST-084 (pin de D16): un nodo atrasado sincroniza por distribución
// una ventana con TRES versiones de contrato del mismo schema
// (Example: v1 → v2 → v3) y el rol de compiler concedido en el último
// evento de la ventana. La adquisición de artefactos se difiere durante
// el catch-up: al llegar a la punta certificada se ejecuta UNA pasada
// que compila solo la versión FINAL — `compiles_received` del scripted
// queda en 1 y los bytes en disco son la v3 del Owner (las versiones
// intermedias nunca se construyen, ni staging ni oficiales). Un
// reinicio posterior arranca con el artefacto presente y los marcadores
// limpios (carga local verificada, cero builds extra) y un fact commitea
// contra la versión final. Sin deferral, el nodo compilaría las tres
// versiones (contador en 3) y el pin fallaría.
async fn test_deferred_acquisition_builds_only_final_contract_version() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();

    let scripted = ScriptedCompiler::start(ScriptedTransform::Identity);

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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(scripted.node_config()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: AveNode2 entra como miembro (sin rol de compiler: los commits
    // de la ventana los cierra el Owner solo, quorum Majority de 1).
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.api.public_key()
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

    // SN 2: alta del schema Example (contrato v1).
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

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: cambio de contrato a la v2.
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

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // SN 4: cambio de contrato a la v3 Y AveNode2 gana el rol de
    // compiler. La fase compile del evento usa los compilers pre-evento
    // (solo el Owner), así que commitea sin AveNode2.
    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "compiler": ["AveNode2"]
                }
            }
        },
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": FUEL_EXHAUSTING_CONTRACT
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

    let artifact_name = format!("{governance_id}_Example");
    let node1_v3 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // AveNode2 sincroniza toda la ventana (SN 1..4) por distribución:
    // los applies difieren la adquisición y al llegar a la punta la
    // pasada compila SOLO la v3 contra el ancla.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v3)
        .await;
    assert_eq!(
        scripted.compiles_received(),
        1,
        "deferred acquisition must build only the final contract version; compiles: {}",
        scripted_compile_log(&scripted)
    );

    // Reinicio: los marcadores quedaron limpios y el artefacto está en
    // disco — carga local verificada contra el ancla, cero builds extra.
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
        compiler: Some(scripted.node_config()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v3)
        .await;
    assert_eq!(scripted.compiles_received(), 1);

    // Un fact commitea contra la versión final (la v3 evalúa ModTwo como
    // el resto de la familia Example).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModTwo": {"data": 5}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 5, "three": 0}));

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-085 (pin de D16): crash en medio de la adquisición diferida.
// AveNode2 (compiler con el pool muerto) sincroniza una ventana con dos
// versiones de contrato: los applies difieren la adquisición (marcador
// `acquisition_pending` persistido, artefacto ausente) y la pasada al
// llegar a la punta intenta la recuperación de compiler con el pool
// muerto → crash-fast (misma política que el apply por lotes). El nodo
// queda caído a mitad de la ventana ampliada después: con el artefacto
// ausente Y el marcador persistido, el reinicio NO compila la versión
// intermedia local NI hace crash-fast (ausente CON marcador = estado
// esperado de un nodo que cayó mid-sync; la rama contraria — ausente
// SIN marcador = crash-fast — la pincha TEST-070). Tras el reboot, la
// sincronización del evento restante dispara la pasada y solo se
// adquiere la versión FINAL (contador del scripted en 1, bytes == v3).
async fn test_deferred_acquisition_crash_mid_sync_recovers_final_only() {
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

    // AveNode2 con el pool muerto desde el principio (patrón TEST-069).
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
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: AveNode2 miembro y compiler; la política de compilación pasa
    // a Fixed(1) para que los commits de contrato cierren con el voto
    // del Owner aunque AveNode2 esté atrasado o caído.
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
                    "compiler": ["AveNode2"]
                }
            }
        },
        "policies": {
            "governance": {
                "change": {
                    "compile": {
                        "fixed": 1
                    }
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

    // SN 2: alta del schema Example (contrato v1).
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

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: cambio de contrato a la v2.
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

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");

    // AveNode2 sincroniza la ventana (SN 1..3): applies diferidos
    // (marcador persistido, artefacto ausente) y la pasada de la punta
    // choca con el pool muerto → crash-fast.
    let _ = node2.api.update_subject(governance_id.clone()).await;
    wait_node_down(&node2.api).await;
    assert!(
        !artifact_dir_exists(node2_contracts.path(), &artifact_name),
        "the deferred pass crashed before building any contract version"
    );

    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    // Mientras AveNode2 está caído la ventana se amplía: SN 4 cambia el
    // contrato a la v3 (commitea con el Owner solo, Fixed(1)).
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_contract": FUEL_EXHAUSTING_CONTRACT
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

    let node1_v3 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // Reboot con pool vivo (scripted): el arranque encuentra el
    // artefacto ausente CON marcador (estado esperado mid-sync) → NO
    // compila la v2 local ni crash-fast; el nodo arranca.
    let scripted = ScriptedCompiler::start(ScriptedTransform::Identity);

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
        compiler: Some(scripted.node_config()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    // La sincronización del evento restante (SN 4) dispara la pasada al
    // llegar a la punta: solo se adquiere la versión FINAL.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v3)
        .await;
    assert_eq!(
        scripted.compiles_received(),
        1,
        "after a mid-sync crash only the final contract version is built; compiles: {}",
        scripted_compile_log(&scripted)
    );

    // La red sigue funcional: un fact commitea contra la versión final.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModTwo": {"data": 5}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 5, "three": 0}));

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-086 (pin de D16): nodo AL DÍA con marcador pendiente. Misma
// situación que TEST-085 (crash de la pasada con el pool muerto,
// marcador persistido, artefacto ausente) pero SIN eventos nuevos
// durante la caída: al reiniciar — aislado de la red, sin peers —
// ninguna ronda de distribución puede firear; es la ronda IDLE de
// version_sync (sin peer por delante = ya está en la punta) la que
// dispara la pasada de adquisición. El compiler compila localmente la
// versión vigente (el build no necesita red): contador del scripted en
// 1 y bytes == v2 del Owner. Un segundo reinicio confirma los
// marcadores limpios: arranque normal con carga local y cero builds.
async fn test_deferred_acquisition_idle_sync_round_at_tip() {
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

    // AveNode2 con el pool muerto desde el principio (patrón TEST-069).
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
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: AveNode2 miembro y compiler; política compile Fixed(1) (los
    // commits cierran con el Owner aunque AveNode2 esté atrasado).
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
                    "compiler": ["AveNode2"]
                }
            }
        },
        "policies": {
            "governance": {
                "change": {
                    "compile": {
                        "fixed": 1
                    }
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

    // SN 2: alta del schema Example (contrato v1).
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

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: cambio de contrato a la v2 (versión vigente desde aquí).
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

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node1_v2 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // AveNode2 sincroniza la ventana completa (queda AL DÍA, SN 3) con
    // adquisición diferida; la pasada choca con el pool muerto → crash.
    let _ = node2.api.update_subject(governance_id.clone()).await;
    wait_node_down(&node2.api).await;
    assert!(
        !artifact_dir_exists(node2_contracts.path(), &artifact_name),
        "the deferred pass crashed before building any contract version"
    );

    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    // Reboot AISLADO (Bootstrap sin peers: patrón canónico de reinicio
    // aislado) con pool vivo. Sin eventos nuevos en la red, ninguna
    // ronda de distribución fireará: la ronda idle de version_sync
    // dispara la pasada y el compiler compila la v2 localmente. El
    // hijo `version_sync` SOLO se crea con `is_service: true`
    // (governance/mod.rs); sin él no hay rondas idle. El intervalo de
    // sync se reduce solo en este nodo para no pagar los 10 s + 5 s
    // por defecto del config de tests.
    let scripted = ScriptedCompiler::start(ScriptedTransform::Identity);

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
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
        compiler: Some(scripted.node_config()),
        is_service: true,
        governance_sync: Some(GovernanceSyncConfig {
            interval_secs: 3,
            sample_size: 3,
            response_timeout_secs: 2,
        }),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;
    assert_eq!(
        scripted.compiles_received(),
        1,
        "the idle sync round must fire exactly one acquisition pass; compiles: {}",
        scripted_compile_log(&scripted)
    );

    // Segundo reinicio aislado: marcadores limpios y artefacto en disco
    // → arranque normal con carga local, cero builds adicionales.
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
        compiler: Some(scripted.node_config()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;
    assert_eq!(scripted.compiles_received(), 1);
}

#[test(tokio::test)]
// TEST-087 (pin de D17): un compiler PURO (nunca evaluator) no retiene
// módulo residente. Tras el commit del schema-add el artefacto está en
// disco (compilado e init-checked) pero el helper `contracts` NO tiene
// el módulo (`test_has_contract_module` false), y sigue así tras un
// reboot (la recovery de arranque verifica contra el ancla y descarta
// el módulo). Serving plan A no usa el módulo: con el Owner silenciado
// (Drop de sus probe-res), AveNode3 fetchea la v1 DE AveNode2 — bytes
// anclados idénticos — mientras AveNode2 sigue sin módulo. Al ganar el
// rol evaluator con todo el tráfico de artefactos hacia él dropeado
// (cualquier fetch se estancaría), AveNode2 carga el módulo desde disco
// (fast path cwasm, verificado contra el ancla, CERO red: nunca existe
// máquina de estados de fetch para el contrato) y evalúa un fact que
// commitea con su voto.
async fn test_pure_compiler_no_resident_module_disk_load_on_role_gain() {
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

    let make_addr =
        || format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst));

    let (mut node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
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

    let (node3, _node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
        peers: vec![RoutingNode {
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();

    // SN 1: miembros y AveNode2 compiler de la gobernanza.
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

    // SN 2: alta del schema Example (v1). Compilers: Owner y AveNode2
    // (Majority de 2, ambos compilan). El único evaluador es AveNode3.
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

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // Compiler puro: artefacto en disco, SIN módulo residente.
    wait_module_resident(&node2.api, &artifact_name, false).await;

    // Reboot: la recovery de arranque verifica el artefacto contra el
    // ancla y tampoco retiene el módulo (AveNode2 no evalúa Example).
    node2.token.cancel();
    join_all(node2.handler.iter_mut()).await;

    let (node2, _node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: make_addr(),
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

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v1)
        .await;
    wait_module_resident(&node2.api, &artifact_name, false).await;

    // Serving plan A sin módulo: con el Owner silenciado, AveNode3
    // fetchea la v1 de AveNode2 (bytes anclados idénticos).
    node3
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.probes_sent, 2);
    assert_eq!(obs.downloads_started, 1);
    node3.api.test_clear_faults().await.unwrap();

    // Servir bytes no instala el módulo en el servidor.
    wait_module_resident(&node2.api, &artifact_name, false).await;

    // Todo el tráfico de artefactos HACIA AveNode2 dropeado: cualquier
    // intento de fetch se estancaría. La carga del módulo al ganar el
    // rol evaluator debe ser local-first (cero red).
    for message in [FaultMessage::ArtifactProbeRes, FaultMessage::ArtifactRes]
    {
        node2
            .api
            .test_install_fault(FaultRule {
                direction: FaultDirection::Inbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // SN 3: AveNode2 gana evaluator y testigo del schema.
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

    // Carga local-first desde disco (fast path cwasm, ancla verificada):
    // el módulo aparece SIN que exista fetch alguno para el contrato.
    wait_module_resident(&node2.api, &artifact_name, true).await;
    assert!(
        node2.api.test_fetch_obs(&artifact_name).await.is_none(),
        "local-first load must not start any fetch"
    );

    node2.api.test_clear_faults().await.unwrap();

    // AveNode3 se pone al día con SN 3 (evalúa el fact final).
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // Un fact commitea con el voto de AveNode2 (Majority de 2 con
    // AveNode3): el módulo cargado desde disco evalúa.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    get_subject(&node3.api, subject_id.clone(), Some(0), true)
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

    let state = get_subject(&node2.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-088 (pin de D17): un nodo compiler+evaluator pierde SOLO el rol
// evaluator. El módulo residente se evicta (`test_has_contract_module`
// false) pero los bytes y el ancla se conservan en disco, y serving
// plan A queda desacoplado de la residencia: con el Owner silenciado,
// AveNode3 fetchea la v1 DE AveNode2 (sigue siendo compiler) mientras
// este no tiene módulo. La red sigue commiteando (fact con el voto de
// AveNode3). Al recuperar el rol, AveNode2 recarga el módulo desde
// disco verificado contra el ancla (cero red: sin fetch) y vuelve a
// evaluar.
async fn test_lose_evaluator_evicts_module_keeps_plan_a_serving() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();

    // SN 1: miembros y AveNode2 compiler de la gobernanza.
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

    // SN 2: alta del schema Example (v1); evaluadores AveNode2 y
    // AveNode3. AveNode2 compila y evalúa: módulo residente.
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

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // Compiler+evaluator: módulo residente.
    wait_module_resident(&node2.api, &artifact_name, true).await;

    // SN 3: AveNode2 pierde SOLO el rol evaluator (conserva compiler).
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

    // Módulo evictado; los bytes del artefacto se conservan en disco.
    wait_module_resident(&node2.api, &artifact_name, false).await;
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // Serving plan A sigue funcionando sin módulo: con el Owner
    // silenciado, AveNode3 fetchea la v1 de AveNode2.
    node3
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;
    node3.api.test_clear_faults().await.unwrap();
    wait_module_resident(&node2.api, &artifact_name, false).await;

    // La red sigue commiteando: un fact con el voto de AveNode3 (único
    // evaluador ahora).
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
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node3.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 3, "two": 0, "three": 0}));

    // SN 4: AveNode2 recupera el rol evaluator → recarga local-first
    // desde disco (bytes retenidos), cero red.
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

    wait_module_resident(&node2.api, &artifact_name, true).await;
    assert!(
        node2.api.test_fetch_obs(&artifact_name).await.is_none(),
        "role regain must reload the module from disk, never fetch"
    );

    // Y vuelve a evaluar: un fact commitea con Majority de 2.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModTwo": {"data": 4}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node2.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 3, "two": 4, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-089 (pin de D17, matriz de roles): un nodo compiler+evaluator
// pierde SOLO el rol compiler. SIGUE evaluando: el módulo permanece
// residente y un fact commitea con su voto. Y DEJA de servir plan A:
// la whitelist de compilers del requester ya no lo incluye — con el
// Owner (único compiler restante) silenciado, el plan A de AveNode3
// queda vacío de respuestas y el fetch completa por plan B desde el
// propio AveNode2, que conserva el rol evaluator y el artefacto (por
// diseño serving plan B no depende del rol compiler; el escenario
// original de la fila —agotar el ciclo porque el degradado no responde
// CanServe— es irrepresentable mientras el nodo conserva el rol
// evaluator: sigue siendo un servidor de plan B legítimo). Al recuperar
// el rol compiler, AveNode2 vuelve a compilar: un cambio de contrato a
// la v2 (quorum Majority de 2, su build es imprescindible) commitea y
// un fact v2-only commitea con su voto.
async fn test_lose_compiler_keeps_evaluating_stops_plan_a_serving() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();

    // SN 1: miembros y AveNode2 compiler de la gobernanza.
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

    // SN 2: alta del schema Example (v1); evaluadores Owner, AveNode2 y
    // AveNode3.
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

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    wait_module_resident(&node2.api, &artifact_name, true).await;

    // Subject y un primer fact: commitea con los votos de Owner y
    // AveNode2 (AveNode3 aún no tiene gobernanza ni artefacto).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
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

    get_subject(&node2.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 3: AveNode2 pierde SOLO el rol compiler (conserva evaluator).
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

    // Perder compiler no toca el módulo: AveNode2 sigue evaluando y un
    // fact commitea con su voto (Majority de 3 = 2: Owner y AveNode2).
    wait_module_resident(&node2.api, &artifact_name, true).await;

    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node2.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 2, "two": 0, "three": 0}));
    wait_module_resident(&node2.api, &artifact_name, true).await;

    // Plan A sin AveNode2: la whitelist de compilers de AveNode3 es
    // solo {Owner}. Con el Owner silenciado, el plan A no responde y el
    // fetch completa por plan B desde AveNode2 (evaluador con
    // artefacto) — sin agotar el ciclo.
    node3
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.cycles_exhausted, 0);
    node3.api.test_clear_faults().await.unwrap();

    // SN 4: AveNode2 recupera el rol compiler.
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
    get_subject(&node2.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // SN 5: cambio de contrato a la v2 — el quorum Majority de 2 exige
    // el build de AveNode2 (rol compiler funcional de nuevo).
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

    get_subject(&node1.api, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    // AveNode2 debe estar en v5 para evaluar el fact final (su voto es
    // imprescindible para el Majority de 3): como no recibe la
    // gobernanza automáticamente, se sincroniza explícitamente igual que
    // tras cada cambio de gobernanza anterior.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    // Un fact que la v1 rechazaría (ModThree=50) commitea con el voto
    // v2 de AveNode2: evalúa con el artefacto que él mismo compiló.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node2.api, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 2, "two": 0, "three": 50}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-090 (pin del offload del build remoto): dos requests de
// compilación CONCURRENTES sobre el mismo compiler remoto y serving
// desbloqueado durante los builds. Los eventos de gobernanza de un
// mismo owner se serializan (un evento no entra en fases hasta que el
// anterior commitea: su estado base depende de él), así que dos
// requests de compilación simultáneas exigen DOS gobernanzas — la fila
// original proponía dos schema-adds en la misma gobernanza,
// irrepresentable (desviación documentada y acordada). Setup:
// gobernanza A (owner node1) con el schema Stable ya commiteado y
// gobernanza B (owner AveNode3); AveNode2 (scripted) es compiler de
// ambas. Con el scripted HELD, un schema-add async en cada gobernanza
// → AMBOS builds llegan a AveNode2 (`compiles_received` pasa de 1 —el
// schema Stable previo— a 3 mientras held): las compilaciones remotas
// corren en workers efímeros por request_id, no serializadas en el
// loop del standing worker. Y el standing worker sigue respondiendo
// durante los builds: con el Owner de A silenciado, el fetch de Stable
// de AveNode3 (plan A contra AveNode2) completa MIENTRAS los dos
// builds están held — pre-offload, probes y serves se encolaban detrás
// del build en el loop del worker. Al liberar, ambos eventos commitean
// sin builds duplicados (contador en 3) y AveNode2 promociona Foo y
// Bar (recover local-first, sin nuevos builds).
async fn test_remote_builds_offloaded_concurrent_and_serving_unblocked() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();

    let scripted = ScriptedCompiler::start(ScriptedTransform::Identity);

    // Fuentes únicas por ejecución: los tres builds deben llegar
    // siempre al scripted (ver `unique_contract`).
    let stable_contract = unique_contract(CHANGED_SCHEMA_CONTRACT);
    let foo_contract = unique_contract(EXAMPLE_CONTRACT);
    let bar_contract = unique_contract(EXAMPLE_CONTRACT_V2);

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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(scripted.node_config()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();

    // SN 1: miembros y AveNode2 compiler de la gobernanza.
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

    // SN 2: schema Stable (contrato propio), evaluado por AveNode3.
    // AveNode2 lo compila vía scripted (primer build del contador).
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Stable",
                    "add": {
                        "evaluator": [
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
                    "id": "Stable",
                    "contract": stable_contract,
                    "initial_value": {
                        "data": ""
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

    // AveNode2 debe APLICAR SN 2: el build de fase va a staging y la
    // promoción al dir oficial ocurre al aplicar el evento (recover
    // local-first del diferido, sin nuevo build). Sin el artefacto
    // oficial no puede servir Stable por plan A a AveNode3.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    wait_compiles_received(&scripted, 1).await;

    let stable_name = format!("{governance_id}_Stable");
    let node1_stable =
        wait_artifact_bytes(node1_contracts.path(), &stable_name).await;
    wait_artifact_bytes_eq(node2_contracts.path(), &stable_name, &node1_stable)
        .await;

    // Gobernanza B (owner AveNode3, AveNode2 compiler): los eventos de
    // gobernanza de un mismo owner se serializan, así que dos requests
    // de compilación concurrentes exigen dos gobernanzas distintas.
    let governance_b_id =
        create_and_authorize_governance(&node3.api, vec![&node2.api]).await;

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
                    "compiler": ["AveNode2"]
                }
            }
        }
    });

    emit_fact(&node3.api, governance_b_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node3.api, governance_b_id.clone(), Some(1), true)
        .await
        .unwrap();

    node2
        .api
        .update_subject(governance_b_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_b_id.clone(), Some(1), true)
        .await
        .unwrap();

    // A partir de aquí el scripted retiene TODAS las respuestas de
    // compilación de AveNode2.
    scripted.hold();

    // AveNode3 fetcheará Stable de AveNode2: el Owner de A queda
    // silenciado.
    node3
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();

    // SN 3 de la gobernanza A y SN 2 de la gobernanza B (ambos async):
    // dos requests de compilación llegan a AveNode2 a la vez.
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Foo",
                    "contract": foo_contract,
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

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Bar",
                    "contract": bar_contract,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        }
    });
    emit_fact(&node3.api, governance_b_id.clone(), json, false)
        .await
        .unwrap();

    // Offload: AMBOS builds remotos arrancan en workers efímeros (el
    // contador llega a 3) a pesar de estar held — con el build inline
    // en el loop del worker, el segundo request no se aceptaría hasta
    // terminar el primero.
    wait_compiles_received(&scripted, 3).await;

    // Serving no se encola detrás de los builds: el fetch de Stable de
    // AveNode3 (plan A contra AveNode2, Owner de A silenciado) completa
    // mientras los dos builds siguen held.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    wait_artifact_bytes_eq(node3_contracts.path(), &stable_name, &node1_stable)
        .await;
    assert_eq!(scripted.compiles_received(), 3);
    node3.api.test_clear_faults().await.unwrap();

    // Al liberar, ambos eventos commitean sin builds duplicados.
    scripted.release();

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    get_subject(&node3.api, governance_b_id.clone(), Some(2), true)
        .await
        .unwrap();

    // AveNode2 aplica ambos eventos: promoción de Foo y Bar desde sus
    // builds previos (recover local-first, sin nuevos builds).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    node2
        .api
        .update_subject(governance_b_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_b_id.clone(), Some(2), true)
        .await
        .unwrap();

    assert_eq!(
        scripted.compiles_received(),
        3,
        "no duplicate builds after releasing the held compiles"
    );

    wait_artifact_bytes(
        node2_contracts.path(),
        &format!("{governance_id}_Foo"),
    )
    .await;
    wait_artifact_bytes(
        node2_contracts.path(),
        &format!("{governance_b_id}_Bar"),
    )
    .await;

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-091 (pin del offload + D15): retry de una request YA aceptada →
// re-ACK sin build duplicado. Se dropea el PRIMER
// `CompilationRes::Working` de AveNode2 (occurrences=1) y se retiene su
// resultado final (Hold, occurrences=1): el coordinator del Owner no
// recibe el ACK, agota su único intento de retry (test: 1×5 s) y
// reenvía la `NetworkRequest`; AveNode2 encuentra el child efímero por
// `request_id` y RE-ENVÍA el Working ACK en vez de compilar de nuevo —
// `compiles_received` permanece en 1 durante todo el test. El re-ACK
// cancela el retry del coordinator (sin re-ACK, el EndRetry lo
// reportaría como timeout y AveNode2 sería descartado: el quorum
// Majority de 2 no cerraría). Al liberar el resultado retenido, la
// request commitea. Espera fija de 8 s: el retry del coordinator firea
// a los 5 s (config de test) y el re-ACK debe llegar antes de soltar
// el resultado.
async fn test_working_ack_retry_finds_child_no_duplicate_build() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let scripted = ScriptedCompiler::start(ScriptedTransform::Identity);

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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(scripted.node_config()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();

    // SN 1: AveNode2 miembro y compiler de la gobernanza.
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

    // Reglas en orden: (1) Drop del primer CompilationRes (el Working
    // ACK); (2) Hold del segundo (el resultado final). El re-ACK del
    // retry ya no encuentra regla y fluye.
    node2
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::CompilationRes,
            peer: Some(node1_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    node2
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::CompilationRes,
            peer: Some(node1_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // SN 2 (async): alta del schema Example. AveNode2 acepta, envía el
    // Working (dropeado), compila y retiene el resultado. Fuente única
    // por ejecución (ver `unique_contract`).
    let example_contract = unique_contract(EXAMPLE_CONTRACT);
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
                    "contract": example_contract,
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

    wait_compiles_received(&scripted, 1).await;

    // El resultado está retenido en AveNode2 y el evento no commitea.
    for _ in 0..100 {
        if node2.api.test_held_count().await.unwrap() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_eq!(node2.api.test_held_count().await.unwrap(), 1);

    // El retry del coordinator (1×5 s en test) reenvía la request a
    // los ~5 s; AveNode2 re-envía el Working ACK del child existente.
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(
        scripted.compiles_received(),
        1,
        "the request retry must re-ACK the existing build, not duplicate it"
    );

    // Liberado el resultado, la request commitea (quorum Majority de 2:
    // Owner y AveNode2).
    assert_eq!(node2.api.test_release_held().await.unwrap(), 1);

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(scripted.compiles_received(), 1);

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-024: desacuerdo entre compilers → Reboot(Diff) → recuperación en
// el reintento. El Owner compila los bytes reales (compilador
// embebido) y AveNode2 RECHAZA el contrato solo en el primer build
// (scripted `InvalidOnce`, error InvalidArgument): el voto de AveNode2
// es un fallo de compilación, mezclado con el Ok del Owner los
// resultados no son idénticos → la fase reporta `Reboot(Diff)`. Como
// el rechazo no cachea nada en ningún sitio, el retry del reboot
// recompila y esta vez AveNode2 sirve el artefacto real: acuerdo y
// commit. Pines: la request alcanza RebootDiff, el reintento commitea
// el evento (SN 2) con exactamente UN build por ciclo (sin
// duplicados), AveNode2 promociona el artefacto oficial al aplicar y
// la gobernanza no se cuelga — un evento posterior sin fase compile
// commitea (SN 3).
// NOTA: una divergencia terminal (scripted `CustomSection`) deja la
// request rebootando para siempre — el schedule de Diff es infinito
// por diseño ([10, 20, 30, 60] s, luego 60 s) — y, al serializarse los
// eventos de gobernanza de un mismo owner, la gobernanza queda
// bloqueada. Y servir bytes distintos para la misma fuente en el
// reintento dispara el cross-check del cliente (trata la divergencia
// como manipulación, no como veredicto): por eso la divergencia
// transitoria es un RECHAZO, no bytes distintos.
async fn test_compiler_disagreement_reboot_diff() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let scripted = ScriptedCompiler::start(ScriptedTransform::InvalidOnce);

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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(scripted.node_config()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: AveNode2 miembro y compiler de la gobernanza.
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

    // SN 2 (async): alta del schema Example. Primer build: AveNode2
    // vota fallo de compilación (rechazo InvalidArgument) contra el Ok
    // del Owner → resultados mezclados → Reboot(Diff). Fuente única
    // por ejecución (ver `unique_contract`).
    let example_contract = unique_contract(EXAMPLE_CONTRACT);
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
                    "contract": example_contract,
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
        emit_fact(&node1.api, governance_id.clone(), json, false)
            .await
            .unwrap();

    wait_request_state(
        &node1.api,
        request_id,
        Some(RequestState::RebootDiff {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // La divergencia era transitoria: el retry del reboot (10 s,
    // primera entrada del schedule) recompila y AveNode2 sirve el
    // artefacto real — acuerdo, commit del evento y exactamente UN
    // build por ciclo (sin duplicados).
    let gov_state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(gov_state.sn, 2);
    assert_eq!(scripted.compiles_received(), 2);

    // El Owner promociona el artefacto oficial al commitear; AveNode2
    // al aplicar el evento (promoción desde su build del retry).
    let artifact_name = format!("{governance_id}_Example");
    let node1_artifact =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_artifact)
        .await;

    // La gobernanza no se cuelga: un evento sin fase compile commitea.
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode3",
                    "key": KeyPair::generate(
                        ave_common::identity::KeyPairAlgorithm::Ed25519
                    )
                    .unwrap()
                    .public_key()
                    .to_string()
                }
            ]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let gov_state = get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(gov_state.sn, 3);

    node_running(&node1.api).await.unwrap();
    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// TEST-032 (pin de D15): compilación más lenta que el presupuesto de
// retry del ACK del coordinator. Con el scripted compiler HELD, el
// worker efímero de AveNode2 envía el `CompilationRes::Working` ANTES
// de compilar: el coordinator cancela el retry de la request y espera
// el resultado bajo `RESULT_DEADLINE` (300 s en test). Durante toda la
// espera (8 s, más que el retry de 1×5 s del coordinator) no hay NI
// reenvíos NI builds duplicados (`compiles_received` se queda en 1 — un
// reenvío encontraría el child y re-ACKaría, así que el contador solo
// puede subir si el coordinator descartara al compiler y recompilara
// por otra vía) NI failover. Al liberar, el compile lento-pero-sano
// commitea con el voto de AveNode2 (quorum Majority de 2). El compile
// que supera `RESULT_DEADLINE` (timeout limpio) no es representable en
// e2e (300 s en test): esa rama queda pineada en unit por TEST-083.
async fn test_slow_compile_working_ack_no_failover_no_duplicate() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();

    let scripted = ScriptedCompiler::start(ScriptedTransform::Identity);

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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(scripted.node_config()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: AveNode2 miembro y compiler de la gobernanza.
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

    scripted.hold();

    // SN 2 (async): alta del schema Example. AveNode2 ACKa (Working) y
    // su build queda held en el scripted. Fuente única por ejecución
    // (ver `unique_contract`).
    let example_contract = unique_contract(EXAMPLE_CONTRACT);
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
                    "contract": example_contract,
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

    wait_compiles_received(&scripted, 1).await;

    // 8 s held (el retry del coordinator firea a los 5 s si no fue
    // cancelado por el ACK): ni reenvíos ni builds duplicados.
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(
        scripted.compiles_received(),
        1,
        "the working ACK must cancel the coordinator retry: no duplicates"
    );

    // Al liberar, el compile lento-pero-sano commitea (quorum Majority
    // de 2: Owner y AveNode2).
    scripted.release();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // AveNode2 aplica SN 2: promoción del artefacto al dir oficial
    // (recover local-first del diferido, sin nuevo build).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    assert_eq!(scripted.compiles_received(), 1);

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v1)
        .await;

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// Alta de dos schemas en el mismo evento con la MISMA fuente en los dos
// formatos admitidos: "Plain" la recibe en plano (base64) y "Packed"
// comprimida (base64(zstd(fuente))). La descompresión es transparente
// al consenso: ambos payloads recorren staging y promoción de verdad y
// producen artefactos byte a byte idénticos en todos los nodos. Pines:
// la request commitea, los bytes del artefacto oficial de Plain y
// Packed coinciden en el Owner y en el evaluador (que compila ambos
// payloads con su propio pool), y los dos schemas crean subjects y
// evalúan facts — el quorum de evaluación exige el voto de los dos
// evaluadores, así que AveNode2 también evalúa con el artefacto que
// compiló desde el payload comprimido.
async fn test_schema_add_compressed_contract_byte_identical() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: un único evento da de alta los dos schemas (misma fuente,
    // plana y comprimida) con AveNode2 como evaluador de ambos.
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
                    "id": "Plain",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Packed",
                    "contract": compressed_contract(EXAMPLE_CONTRACT),
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
                schema_roles("Plain"),
                schema_roles("Packed")
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

    // Mismo wasm en el Owner para los dos formatos: la compresión no
    // cambia ni un byte del artefacto.
    let plain_name = format!("{governance_id}_Plain");
    let packed_name = format!("{governance_id}_Packed");
    let plain_bytes =
        wait_artifact_bytes(node1_contracts.path(), &plain_name).await;
    let packed_bytes =
        wait_artifact_bytes(node1_contracts.path(), &packed_name).await;
    assert_eq!(
        plain_bytes, packed_bytes,
        "the compressed format must produce a byte-identical artifact"
    );

    // AveNode2 compiló ambos payloads con su pool y promocionó los
    // mismos bytes que el Owner.
    wait_artifact_bytes_eq(node2_contracts.path(), &plain_name, &plain_bytes)
        .await;
    wait_artifact_bytes_eq(node2_contracts.path(), &packed_name, &plain_bytes)
        .await;

    // Ambos schemas crean subjects y evalúan facts (quorum Majority de
    // evaluación: votan Owner y AveNode2).
    for (schema_id, value) in [("Plain", 11), ("Packed", 22)] {
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

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// Divergencia terminal entre compilers: el Owner compila los bytes
// reales (pool embebido) y AveNode2/AveNode3 compilan la misma fuente
// con sus scripted (`CustomSection` con tags distintos), así que los
// tres votan Ok con tres wasm_hash distintos que nunca coinciden en un
// único hash y la fase de compilación reporta Reboot(Diff) en cada
// intento. (El Owner no puede perder el rol compiler: es un rol básico
// protegido de la gobernanza — quitarlo haría el evento inválido.)
// La política de compilación se fija al 100 % porque el coordinator
// pregunta a un subconjunto aleatorio del tamaño del quórum: con
// Majority de 3 solo compilarían 2 y los contadores de los scripted
// no serían deterministas. El schedule de Diff es infinito
// por diseño ([10, 20, 30, 60] s y luego 60 s): la request queda
// rebootando para siempre y, al serializarse los eventos de gobernanza
// de un mismo owner, la gobernanza queda bloqueada — un fallo
// controlado y accionable, no un crash. Pines: la request alcanza
// RebootDiff, el SN de la gobernanza no avanza, ningún nodo promociona
// el artefacto oficial del schema (nadie evalúa con un artefacto no
// anclado) y los votos divergentes quedan cacheados: tras cubrir el
// primer reintento (10 s) cada scripted sigue habiendo recibido
// exactamente UN compile — los reboots no recompilan. El test termina
// con la request rebootando en background, por diseño.
async fn test_compiler_terminal_divergence_reboot_diff_wedged() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();

    // Mismo transform con tags distintos: wasm válido y equivalente en
    // comportamiento, pero con bytes (y hash) divergentes por nodo.
    let scripted_a =
        ScriptedCompiler::start(ScriptedTransform::CustomSection("a".to_owned()));
    let scripted_b =
        ScriptedCompiler::start(ScriptedTransform::CustomSection("b".to_owned()));

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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(scripted_a.node_config()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        compiler: Some(scripted_b.node_config()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    // SN 1: AveNode2 y AveNode3 miembros y además compilers de la
    // gobernanza. El Owner conserva su rol compiler (protegido), así
    // que la fase de compilación reunirá tres votos Ok con tres hashes
    // distintos — la divergencia terminal es la misma.
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
                    "compiler": ["AveNode2", "AveNode3"]
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

    for node in [&node2.api, &node3.api] {
        node.update_subject(governance_id.clone()).await.unwrap();
        get_subject(node, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    // SN 2: la política de compilación pasa al 100 % para que el
    // coordinator pregunte siempre a los tres compilers (ver el
    // comentario de cabecera).
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "compile": {
                        "percentage": 100
                    }
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

    for node in [&node2.api, &node3.api] {
        node.update_subject(governance_id.clone()).await.unwrap();
        get_subject(node, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    // SN 3 (async): alta del schema Example. Los tres compilers votan
    // Ok con wasm_hash distintos → Reboot(Diff), y la divergencia es
    // terminal: cada reintento reproduce los mismos votos. Fuente única
    // por ejecución (ver `unique_contract`): los contadores del
    // scripted son el pin del test.
    let example_contract = unique_contract(EXAMPLE_CONTRACT);
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
                    "contract": example_contract,
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
        emit_fact(&node1.api, governance_id.clone(), json, false)
            .await
            .unwrap();

    wait_request_state(
        &node1.api,
        request_id,
        Some(RequestState::RebootDiff {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    // Cubre el primer reintento del schedule de Diff (10 s): con los
    // votos cacheados el retry vuelve a Reboot(Diff) sin recompilar.
    tokio::time::sleep(Duration::from_secs(12)).await;

    // La gobernanza queda bloqueada en el SN previo al alta del schema:
    // la divergencia terminal impide commitear el evento y los eventos
    // del mismo owner se serializan tras él.
    let gov_state = get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(gov_state.sn, 2);

    // Nadie promociona el artefacto oficial del schema: sin acuerdo de
    // compilación no hay artefacto anclado y ningún nodo evalúa con él.
    let artifact_name = format!("{governance_id}_Example");
    assert!(!artifact_dir_exists(node1_contracts.path(), &artifact_name));
    assert!(!artifact_dir_exists(node2_contracts.path(), &artifact_name));
    assert!(!artifact_dir_exists(node3_contracts.path(), &artifact_name));

    // Los votos divergentes quedan cacheados: el reintento de los 10 s
    // no ha generado ningún compile nuevo en ninguno de los scripted.
    assert_eq!(scripted_a.compiles_received(), 1);
    assert_eq!(scripted_b.compiles_received(), 1);
}

#[test(tokio::test)]
// El barrido de artefactos del arranque limpia el ROOT del directorio
// de contratos: los restos `{gov}_{schema}_temp_promote` y
// `{gov}_{schema}_temp_build_*` (directorios temporales de una promoción
// o un build interrumpidos) no son entradas permitidas y se borran,
// mientras que el artefacto oficial — que vive en
// `contracts/{gov}_{schema}/` — queda intacto. Pines: tras el reinicio
// ambos directorios basura han desaparecido, los bytes del artefacto
// oficial son exactamente los de antes del reinicio y el nodo evalúa
// facts con normalidad (carga el módulo desde el artefacto en disco).
async fn test_boot_sweep_removes_temp_promote_and_build_leftovers() {
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

    // SN 1: schema Example con sus roles. El artefacto oficial queda
    // promovido en `contracts/{gov}_Example/`.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let official_bytes =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    // Restos de una promoción y un build interrumpidos, en el ROOT del
    // directorio de contratos (el barrido solo recorre esa raíz; los
    // artefactos oficiales están un nivel más abajo, en `contracts/`).
    let junk_promote = node1_contracts
        .path()
        .join(format!("{governance_id}_Example_temp_promote"));
    let junk_build = node1_contracts
        .path()
        .join(format!("{governance_id}_Example_temp_build_999"));
    fs::create_dir_all(&junk_promote).unwrap();
    fs::write(junk_promote.join("contract.wasm"), b"junk").unwrap();
    fs::create_dir_all(&junk_build).unwrap();
    fs::write(junk_build.join("contract.wasm"), b"junk").unwrap();

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

    // El barrido corre durante el arranque de la gobernanza: ambos
    // restos desaparecen.
    for _ in 0..100 {
        if !junk_promote.exists() && !junk_build.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        !junk_promote.exists(),
        "the boot sweep must remove the temp_promote leftover"
    );
    assert!(
        !junk_build.exists(),
        "the boot sweep must remove the temp_build leftover"
    );

    // El artefacto oficial queda intacto, byte a byte.
    wait_artifact_bytes_eq(
        node1_contracts.path(),
        &artifact_name,
        &official_bytes,
    )
    .await;

    // Y el nodo queda operativo: recupera la gobernanza en su SN y
    // evalúa un fact cargando el módulo desde el artefacto en disco.
    let gov_state = get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(gov_state.sn, 1);

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
}

#[test(tokio::test)]
// Ledger mixto plano→comprimido con reboot: el schema nace con la v1 en
// plano (base64) y el cambio de contrato trae la v2 comprimida
// (base64(zstd(fuente))). El Owner compila ambas; AveNode2 arranca con
// el pool de compilación muerto y NUNCA recompila: obtiene la v1 y la
// v2 por fetch (verificadas contra el ancla del ledger) y evalúa con
// ellas. Tras un reinicio con el pool aún muerto recupera artefacto y
// ancla del ledger mixto desde disco y sigue evaluando — con el pool
// muerto cualquier recompilación fallaría, así que un fact commiteado
// post-reinicio prueba que no recompiló. Pines: los bytes de la v2 en
// AveNode2 son idénticos a los del Owner, un fact que la v1 rechaza
// (ModThree=50) commitea con el visto bueno de ambos evaluadores y,
// tras el reinicio, el nodo recupera su estado y otro fact commitea.
async fn test_fetch_mixed_ledger_plain_to_compressed_with_reboot() {
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

    // AveNode2 con el pool de compilación muerto desde el arranque:
    // nunca podrá compilar, todo artefacto le llega por fetch.
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: schema Example con la v1 en plano; AveNode2 evaluador y
    // testigo del schema.
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

    // Con el pool muerto, la v1 llega a AveNode2 por fetch (los mismos
    // bytes que compiló el Owner).
    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // SN 2: cambio de contrato a la v2 COMPRIMIDA. El Owner la compila
    // (la descompresión es transparente) y AveNode2 registra el ancla
    // nueva y arranca el fetch al aplicar el evento.
    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": compressed_contract(EXAMPLE_CONTRACT_V2)
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
    assert_ne!(node1_v2, node1_v1);

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El fetch trae a AveNode2 los bytes de la v2 compilada desde el
    // payload comprimido, idénticos a los del Owner.
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v2)
        .await;

    // Un fact que la v1 rechazaría (ModThree=50) commitea: ambos
    // evaluadores votan con el módulo v2.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
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

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    // Esperar a que AveNode2 aplique el evento antes de apagarlo:
    // reiniciar un nodo desincronizado degrada todo lo posterior.
    get_subject(&node2.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Reinicio de AveNode2 conservando contratos y con el pool muerto:
    // el arranque carga el artefacto v2 desde disco.
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
            peer_id: node1.api.peer_id().to_string(),
            address: vec![node1.listen_address.clone()],
        }],
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node2_dirs.append(&mut node2_dirs_new);
    node_running(&node2.api).await.unwrap();

    // Recupera artefacto y ancla del ledger mixto desde disco, sin
    // recompilar (con el pool muerto, un intento de build fallaría).
    let gov_state = get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(gov_state.sn, 2);

    // Otro fact commitea con el visto bueno de AveNode2: evalúa con la
    // v2 cargada del artefacto en disco tras el reinicio.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 60}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 60}));

    get_subject(&node2.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    node_running(&node2.api).await.unwrap();
}


#[test(tokio::test)]
// Un servidor plan B que sirve SIEMPRE bytes corruptos (fault
// `CorruptWasm` outbound sin límite: el wasm viaja corrupto pero el
// zstd es válido, así que el receptor lo detecta por hash contra el
// ancla) deja al fetcher ciclando para siempre: cada ciclo sondea,
// descarga, descarta por hash y quema al peer, agota el ciclo y entra
// en timeoff. Como el plan A (Owner) tiene el directorio oculto y no
// sirve, no hay ninguna fuente sana. Pines: tras varios ciclos el
// requester no ha persistido NADA (los bytes que no casan con el ancla
// se rechazan sin tocar disco), la observabilidad del fetch muestra
// ciclos agotados y descargas repetidas, la gobernanza sigue operativa
// para el resto de schemas (un fact de otro schema commitea) y ambos
// nodos siguen respondiendo — no hay fuga observable de ciclos que
// tumbe al nodo. El test termina con el fetch ciclando en background y
// el fault instalado, por diseño.
async fn test_fetch_always_corrupt_plan_b_server_cycles_without_persisting() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let node3_pk = PublicKey::from_str(node3.api.public_key()).unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    // SN 1: dos schemas. Example lo evalúan AveNode2 y AveNode3 (el
    // Owner NO es evaluador: el plan B de AveNode3 es exactamente
    // {AveNode2} y el plan A es {Owner}); Other lo evalúa solo el
    // Owner — es el testigo de que la gobernanza sigue operativa
    // mientras el fetch de Example cicla.
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
                    "id": "Other",
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

    // AveNode2 aplica SN 1 y fetchea la v1 (la servirá como plan B).
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

    // SN 2: evento ajeno (alta de miembro sin roles). El fetch de
    // AveNode2 calentó la caché de serving del Owner con los bytes
    // sanos (TTL 300 s); aplicar este evento bloquea el serving durante
    // el apply y la vacía — sin esto el Owner seguiría sirviendo desde
    // caché con el directorio oculto.
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

    // AveNode2 aplica SN 2: si se quedara atrasado su gate de serving
    // respondería NotServed a los probes de AveNode3. El contrato no
    // cambia: conserva el artefacto sin refetch (skip guard).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El plan A no puede servir: caché vacía (SN 2) y directorio oculto
    // → serve None, sin rellenar la caché. El artefacto de AveNode2 en
    // disco está ÍNTEGRO: la corrupción se inyecta en la red, en cada
    // respuesta de artefacto hacia AveNode3, sin límite de ocurrencias.
    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    node2
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: Some(node3_pk),
            remaining: None,
            action: FaultAction::CorruptWasm,
        })
        .await
        .unwrap();

    // AveNode3 sincroniza hasta la punta: arranca el fetch de la v1 con
    // la única fuente disponible sirviendo bytes corruptos en cada
    // ciclo.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Varias rondas de probe→descarga→descarte→timeoff (probes y
    // transferencias son instantáneos en memoria y el timeoff base es
    // 1 s).
    tokio::time::sleep(Duration::from_secs(12)).await;

    // Nada se persiste: todo byte que no casa con el ancla se rechaza.
    assert!(
        !artifact_dir_exists(node3_contracts.path(), &artifact_name),
        "las transferencias corruptas se rechazan siempre: nada persiste"
    );

    // El fetch sigue ciclando: ciclos agotados y descargas repetidas
    // (una por ciclo, cada una rechazada por hash).
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.cycles_exhausted >= 1 && obs.downloads_started >= 2
    })
    .await;
    assert!(obs.cycles_exhausted >= 1);
    assert!(obs.downloads_started >= 2);

    // La gobernanza sigue operativa para el resto de schemas: un fact
    // de Other commitea con su evaluador (el Owner).
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Other", "", true)
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

    // Ni el servidor corrupto ni el requester estancado se degradan.
    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// Heal de un compiler con el pool muerto: la verificación pre-serve
// detecta que el artefacto oficial de AveNode2 en disco no casa con el
// ancla registrada (alguien lo corrompió), lo descarta y programa el
// heal — un compiler se cura RECOMPILANDO contra el ancla del ledger.
// Con el pool muerto el heal falla por infraestructura y reintenta con
// backoff sin rendirse; mientras tanto el servidor responde NotServed y
// la gobernanza sigue operativa. Al reiniciar con el pool vivo
// (compilador embebido: el config sin endpoints lo inyecta) la
// recuperación de arranque recompila anclado, el fetcher completa por
// fin la descarga con bytes verificados y un fact commitea con su voto.
// Pines: el artefacto descartado desaparece del disco de AveNode2, el
// fetcher no persiste nada durante la ventana, un evento ajeno de
// gobernanza commitea en plena ventana, el nodo herido no se cae, y
// tras el reboot con pool vivo los bytes curados son exactamente los
// anclados (compilación determinista).
async fn test_serve_corruption_heal_dead_pool_recovers_with_live_pool() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node2_local = tempfile::tempdir().unwrap();
    let node2_ext = tempfile::tempdir().unwrap();
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        local_db: Some(node3_local.path().to_path_buf()),
        ext_db: Some(node3_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    // SN 1: AveNode2 compiler de la gobernanza (Owner y AveNode2
    // compilarán el schema).
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

    // SN 2: alta del schema. AveNode3 evalúa con el Owner (quórum de 2).
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // AveNode2 promociona su build al aplicar; AveNode3 fetchea la v1.
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v1)
        .await;

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // SN 3: evento ajeno para vaciar las cachés de serving que los
    // fetches anteriores pudieron calentar (se vacían al aplicar).
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

    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    for node in [&node2.api, &node3.api] {
        node.update_subject(governance_id.clone()).await.unwrap();
        get_subject(node, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
    }

    // AveNode2 reinicia con el pool de compilación MUERTO: el artefacto
    // está íntegro en disco, así que el arranque no necesita compilar.
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
        compiler: Some(CompilerNodeConfig {
            endpoints: vec!["http://127.0.0.1:1".to_owned()],
            ..Default::default()
        }),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    // Se corrompe el wasm oficial de AveNode2 en disco con el nodo vivo
    // (su caché de serving está vacía: no ha servido desde el SN 3).
    // El plan A del Owner queda oculto para que AveNode2 sea la única
    // fuente posible del refetch de AveNode3.
    let node2_wasm = node2_contracts
        .path()
        .join("contracts")
        .join(&artifact_name)
        .join("contract.wasm");
    fs::write(&node2_wasm, b"corrupted served artifact bytes").unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // AveNode3 pierde su artefacto y reinicia: la recovery de arranque
    // del evaluador refetchea. Al pedir a AveNode2, la verificación
    // pre-serve de AveNode2 detecta su propia corrupción: descarta el
    // artefacto y programa el heal (recompilar anclado), que con el
    // pool muerto falla y reintenta con backoff sin rendirse.
    let (mut node3, _node3_dirs) = (node3, _node3_dirs);
    node3.token.cancel();
    join_all(node3.handler.iter_mut()).await;

    fs::remove_dir_all(
        node3_contracts
            .path()
            .join("contracts")
            .join(&artifact_name),
    )
    .unwrap();

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

    // Ventana de reintentos del heal (base 1 s en test): el artefacto
    // corrupto fue descartado y nada sano lo repone mientras el pool
    // siga muerto.
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert!(
        !artifact_dir_exists(node2_contracts.path(), &artifact_name),
        "la verificación pre-serve descarta el artefacto corrupto"
    );
    assert!(
        !artifact_dir_exists(node3_contracts.path(), &artifact_name),
        "el fetcher no persiste nada mientras nadie sirve bytes anclados"
    );
    node_running(&node2.api).await.unwrap();

    // La gobernanza sigue operativa con el heal reintentando: un evento
    // ajeno commitea y ambos nodos lo aplican (quedan en la versión que
    // sus gates de serving exigirán tras la cura).
    let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode5",
                    "key": key
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

    for node in [&node2.api, &node3.api] {
        node.update_subject(governance_id.clone()).await.unwrap();
        get_subject(node, governance_id.clone(), Some(4), true)
            .await
            .unwrap();
    }

    // Reboot de AveNode2 con el pool vivo (sin config de compiler: el
    // compilador embebido se inyecta por defecto). La recuperación de
    // arranque recompila anclado el artefacto ausente.
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

    // Cura completa: los bytes recompilados son exactamente los
    // anclados.
    let healed =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(
        healed, node1_v1,
        "la recompilación anclada reproduce los bytes originales"
    );

    // AveNode3 completa el fetch desde el AveNode2 curado (el Owner
    // sigue oculto: AveNode2 es la única fuente) con bytes verificados
    // contra el ancla.
    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // El Owner vuelve a servir y un fact commitea con el quórum de los
    // dos evaluadores: AveNode3 evalúa con el artefacto refetcheado.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

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
    assert_eq!(state.properties, json!({"one": 5, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// Self-heal de un evaluador por la vía FETCH: la verificación pre-serve
// detecta que el artefacto oficial de AveNode2 en disco no casa con el
// ancla (lo sirve como plan B a AveNode3), lo descarta y reprovisiona —
// un evaluador se cura REFETCHEANDO de una fuente sana, no compilando.
// El descarte evicta también el módulo en memoria: el nodo no responde
// por unos bytes que ya no verifican contra el ancla, así que durante
// la ventana de heal (Owner sin servir) AveNode2 NO evalúa y su
// heal-fetch cicla. Al restaurar el serving del Owner, el heal-fetch
// completa con bytes anclados, AveNode2 recupera el módulo y vuelve a
// servir, y AveNode3 completa su fetch. Pines: el artefacto corrupto
// desaparece del disco de AveNode2 (detección al servir), el módulo
// evictado durante la ventana, los bytes curados son los anclados y un
// fact commitea con los tres evaluadores ya sanos.
async fn test_evaluator_serve_corruption_self_heals_by_fetch() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    // SN 1: schema Example. Evaluadores iniciales: Owner y AveNode2
    // (AveNode3 se añadirá como evaluador más tarde, forzando su fetch
    // y el plan B de AveNode2).
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

    // AveNode2 fetchea la v1 sana; AveNode3 se sincroniza (es miembro,
    // aún sin rol de evaluador: no fetchea).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &node1_v1)
        .await;

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Subject de Example: baseline operativa con los dos evaluadores.
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

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 0, "three": 0}));

    // SN 2: evento ajeno para vaciar las cachés de serving que los
    // fetches anteriores calentaron (se vacían al aplicar).
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

    for node in [&node2.api, &node3.api] {
        node.update_subject(governance_id.clone()).await.unwrap();
        get_subject(node, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    // Se corrompe el wasm oficial de AveNode2 (su caché de serving está
    // vacía desde el SN 2: el próximo serve leerá de disco) y el plan A
    // del Owner queda oculto: AveNode2 será la única fuente posible del
    // fetch de AveNode3, hasta que se detecte la corrupción.
    let node2_wasm = node2_contracts
        .path()
        .join("contracts")
        .join(&artifact_name)
        .join("contract.wasm");
    fs::write(&node2_wasm, b"corrupted served artifact bytes").unwrap();

    let node1_dir = node1_contracts
        .path()
        .join("contracts")
        .join(&artifact_name);
    let node1_hidden = node1_dir.with_extension("bak");
    fs::rename(&node1_dir, &node1_hidden).unwrap();

    // SN 3: AveNode3 gana el rol de evaluador. Al aplicar necesita la
    // v1: plan A NotServed (oculto) y plan B AveNode2, cuya verificación
    // pre-serve detecta su propia corrupción → descarta el artefacto y
    // su heal (es evaluador: FETCH) queda ciclando mientras el Owner
    // siga oculto.
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

    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // Ventana de heal: el artefacto corrupto fue descartado (detección
    // al servir) y nada sano lo repone mientras el Owner no sirva.
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert!(
        !artifact_dir_exists(node2_contracts.path(), &artifact_name),
        "la verificación pre-serve descarta el artefacto corrupto"
    );
    assert!(
        !artifact_dir_exists(node3_contracts.path(), &artifact_name),
        "el fetcher no persiste nada mientras nadie sirve bytes anclados"
    );

    // El descarte evicta también el módulo en memoria: durante el heal
    // AveNode2 no evalúa (no responde por bytes que ya no verifican
    // contra el ancla) y su heal-fetch cicla mientras el Owner no sirva.
    assert!(
        !node2.api.test_has_contract_module(&artifact_name).await,
        "el módulo se evicta con el descarte: no se evalúa durante el heal"
    );
    assert!(
        node2
            .api
            .test_fetch_obs(&artifact_name)
            .await
            .is_some_and(|obs| obs.cycles_exhausted >= 1),
        "el heal por fetch está ciclando mientras el Owner no sirve"
    );

    // El Owner vuelve a servir: el heal-fetch de AveNode2 completa con
    // bytes anclados y AveNode2 vuelve a servir.
    fs::rename(&node1_hidden, &node1_dir).unwrap();

    let healed =
        wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;
    assert_eq!(
        healed, node1_v1,
        "el self-heal del evaluador repone los bytes anclados"
    );
    wait_module_resident(&node2.api, &artifact_name, true).await;

    // AveNode3 completa su fetch (plan A o plan B ya sanos) y carga el
    // módulo.
    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;
    wait_module_resident(&node3.api, &artifact_name, true).await;

    // Y evalúa: un fact commitea con los tres evaluadores al día.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 3, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// DropSchema con el fetch del contrato EN VUELO: AveNode2 acaba de
// ganar el rol de evaluador de "Doomed" y está ciclando su fetch (la
// única fuente, el Owner, no sirve) cuando el evento que elimina el
// schema commitea. Al aplicarlo, el fetch se cancela y no se reanuda
// para un schema muerto: restaurar el serving NO hace aparecer ningún
// artefacto, no queda staging huérfano y la recovery de arranque no
// intenta resucitarlo. Pines: el fetch estaba ciclando antes del drop
// (observabilidad), tras aplicar el drop el schema desaparece de las
// propiedades de la gobernanza y no aparece artefacto ni resto en disco
// — ni entonces ni tras un reinicio con el serving restaurado — y la
// gobernanza sigue commiteando (un schema vivo evalúa facts antes y
// después del reinicio).
async fn test_drop_schema_cancels_inflight_fetch_no_resurrection() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        local_db: Some(node2_local.path().to_path_buf()),
        ext_db: Some(node2_ext.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    // SN 1: dos schemas. "Doomed" lo evalúa solo el Owner (AveNode2
    // ganará el rol justo antes del drop, sin haber fetcheado nunca);
    // "Other" lo evalúan Owner y AveNode2 — es el schema vivo que sigue
    // commiteando tras el drop.
    let schema_roles = |evaluators: serde_json::Value| {
        json!({
            "add": {
                "evaluator": evaluators,
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
                    "id": "Doomed",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Other",
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
                    "schema_id": "Doomed",
                    "add": schema_roles(json!([
                        {
                            "name": "Owner",
                            "namespace": []
                        }
                    ]))["add"]
                },
                {
                    "schema_id": "Other",
                    "add": schema_roles(json!([
                        {
                            "name": "Owner",
                            "namespace": []
                        },
                        {
                            "name": "AveNode2",
                            "namespace": []
                        }
                    ]))["add"]
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

    // AveNode2 aplica SN 1: fetchea "Other" (es evaluador) pero no
    // "Doomed".
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let other_name = format!("{governance_id}_Other");
    wait_artifact_bytes(node2_contracts.path(), &other_name).await;

    // Subject del schema vivo: baseline operativa.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Other", "", true)
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

    let state = get_subject(&node1.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 1, "two": 0, "three": 0}));

    // El Owner deja de servir "Doomed" (directorio oculto; su caché de
    // serving de ese contrato está vacía: nadie lo ha fetcheado nunca).
    let doomed_name = format!("{governance_id}_Doomed");
    let node1_doomed = node1_contracts
        .path()
        .join("contracts")
        .join(&doomed_name);
    let node1_doomed_hidden = node1_doomed.with_extension("bak");
    fs::rename(&node1_doomed, &node1_doomed_hidden).unwrap();

    // SN 2: AveNode2 gana el rol de evaluador de "Doomed". Al aplicarlo
    // arranca el fetch del contrato, que cicla: la única fuente (el
    // Owner, como compiler y como evaluador) no sirve.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Doomed",
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

    // El fetch de "Doomed" está en vuelo y ciclando (cada ciclo agota
    // los candidatos: nadie sirve).
    wait_fetch_obs(&node2.api, &doomed_name, |obs| {
        obs.cycles_exhausted >= 1
    })
    .await;
    assert!(!artifact_dir_exists(node2_contracts.path(), &doomed_name));

    // SN 3: se elimina el schema con el fetch en vuelo.
    let json = json!({
        "schemas": {
            "remove": ["Doomed"]
        }
    });

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    let gov = governance_properties(state.properties);
    assert!(
        !gov.schemas
            .contains_key(&SchemaType::Type("Doomed".to_owned())),
        "el schema eliminado desaparece de la gobernanza"
    );

    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // El serving del Owner vuelve: si el fetch no se hubiera cancelado,
    // el siguiente ciclo persistiría el artefacto. No aparece nada.
    fs::rename(&node1_doomed_hidden, &node1_doomed).unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;

    let doomed_leftovers = |root: &std::path::Path| -> Vec<String> {
        let mut names = vec![];
        for dir in [root.to_path_buf(), root.join("contracts")] {
            if let Ok(entries) = fs::read_dir(dir) {
                names.extend(entries.flatten().map(|e| {
                    e.file_name().to_string_lossy().into_owned()
                }));
            }
        }
        names
            .into_iter()
            .filter(|name| name.contains("Doomed"))
            .collect()
    };
    assert!(
        doomed_leftovers(node2_contracts.path()).is_empty(),
        "el fetch cancelado no deja artefacto ni staging huérfano"
    );

    // La gobernanza sigue commiteando: un fact del schema vivo commitea
    // con el quórum de sus dos evaluadores.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 2, "two": 0, "three": 0}));

    // Reinicio de AveNode2: la recovery no intenta resucitar el schema
    // eliminado — sin artefacto, sin restos en disco y nodo operativo.
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

    let gov_state = get_subject(&node2.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(gov_state.sn, 3);
    assert!(
        doomed_leftovers(node2_contracts.path()).is_empty(),
        "la recovery de arranque no resucita el schema eliminado"
    );

    // Y el nodo sigue evaluando el schema vivo tras el reinicio.
    emit_fact(
        &node1.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node1.api, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 3, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
}


#[test(tokio::test)]
// Las anclas de compilación y la metadata de artefactos que persiste el
// ContractRegister son una proyección reconstruible del ledger: el test
// las borra directamente de la base de datos local con el nodo apagado
// (borrado selectivo por gobernanza) y verifica que el arranque se
// recupera solo. Tres schemas con contratos commiteados a distinta
// altura (Alpha en SN 1 con cambio de contrato en SN 8, Beta en SN 4 y
// Gamma en SN 6, con eventos ajenos intercalados hasta SN 9) dejan
// anclas de distinta edad; con lotes de ledger de 4 la re-derivación
// del arranque recorre varios lotes hacia atrás buscando la evidencia
// de compilación de cada contrato. Pines: el nodo arranca, la
// gobernanza conserva los tres schemas, los artefactos en disco quedan
// byte a byte idénticos (el arranque los verifica contra el ancla
// re-derivada y re-registra la metadata sin tocar los bytes) y un fact
// por schema commitea. Que el arranque no lance builds del pool no es
// asertable desde aquí: el pool embebido de tests no expone su contador
// a través de la Api del nodo; el pin observable es artefacto idéntico
// y evaluación correcta.
async fn test_boot_anchor_rederivation_after_register_wipe() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node1_local = tempfile::tempdir().unwrap();
    let node1_ext = tempfile::tempdir().unwrap();

    // Lotes de ledger pequeños: la re-derivación de anclas del arranque
    // recorre el ledger hacia atrás en lotes de este tamaño y con el SN
    // final del test debe cruzar varios.
    let (mut node1, _node1_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        local_db: Some(node1_local.path().to_path_buf()),
        ext_db: Some(node1_ext.path().to_path_buf()),
        contracts_path: Some(node1_contracts.path().to_path_buf()),
        ledger_batch_size: Some(4),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![]).await;

    // Fact de alta de un schema con el Owner en todos los roles, y fact
    // de evento ajeno barato (alta de miembro con clave generada).
    let schema_fact = |schema_id: &str, contract: &str| {
        json!({
            "schemas": {
                "add": [
                    {
                        "id": schema_id,
                        "contract": contract,
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
                    }
                ]
            }
        })
    };
    let member_fact = |name: &str| {
        json!({
            "members": {
                "add": [
                    {
                        "name": name,
                        "key": KeyPair::Ed25519(
                            Ed25519Signer::generate().unwrap()
                        )
                        .public_key()
                        .to_string()
                    }
                ]
            }
        })
    };

    // SN 1: schema Alpha con la v1 del contrato de ejemplo.
    emit_fact(
        &node1.api,
        governance_id.clone(),
        schema_fact("Alpha", EXAMPLE_CONTRACT),
        true,
    )
    .await
    .unwrap();
    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let alpha_name = format!("{governance_id}_Alpha");
    let alpha_v1 = wait_artifact_bytes(node1_contracts.path(), &alpha_name).await;

    // SN 2 y 3: eventos ajenos a los contratos.
    emit_fact(&node1.api, governance_id.clone(), member_fact("Extra1"), true)
        .await
        .unwrap();
    emit_fact(&node1.api, governance_id.clone(), member_fact("Extra2"), true)
        .await
        .unwrap();
    get_subject(&node1.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // SN 4: schema Beta con la v2.
    emit_fact(
        &node1.api,
        governance_id.clone(),
        schema_fact("Beta", EXAMPLE_CONTRACT_V2),
        true,
    )
    .await
    .unwrap();
    get_subject(&node1.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
    let beta_name = format!("{governance_id}_Beta");
    let beta_bytes =
        wait_artifact_bytes(node1_contracts.path(), &beta_name).await;

    // SN 5: otro evento ajeno.
    emit_fact(&node1.api, governance_id.clone(), member_fact("Extra3"), true)
        .await
        .unwrap();

    // SN 6: schema Gamma, otra vez con la v1 (misma fuente que Alpha:
    // el artefacto debe ser idéntico).
    emit_fact(
        &node1.api,
        governance_id.clone(),
        schema_fact("Gamma", EXAMPLE_CONTRACT),
        true,
    )
    .await
    .unwrap();
    get_subject(&node1.api, governance_id.clone(), Some(6), true)
        .await
        .unwrap();
    let gamma_name = format!("{governance_id}_Gamma");
    let gamma_bytes =
        wait_artifact_bytes(node1_contracts.path(), &gamma_name).await;
    assert_eq!(
        gamma_bytes, alpha_v1,
        "misma fuente de contrato, mismo artefacto"
    );

    // SN 7: otro evento ajeno.
    emit_fact(&node1.api, governance_id.clone(), member_fact("Extra4"), true)
        .await
        .unwrap();

    // SN 8: cambio de contrato de Alpha a la v2 — una ancla reciente
    // sobre el schema más viejo. La promoción reemplaza el artefacto
    // oficial: se espera a que los bytes cambien.
    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Alpha",
                    "new_contract": EXAMPLE_CONTRACT_V2
                }
            ]
        }
    });
    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    let alpha_dir = node1_contracts.path().join("contracts").join(&alpha_name);
    let mut alpha_v2 = alpha_v1.clone();
    for _ in 0..100 {
        if alpha_dir.join("contract.cwasm").exists()
            && let Ok(bytes) = fs::read(alpha_dir.join("contract.wasm"))
            && bytes != alpha_v1
        {
            alpha_v2 = bytes;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert_ne!(
        alpha_v2, alpha_v1,
        "el cambio de contrato debe reemplazar el artefacto de Alpha"
    );
    assert_eq!(
        alpha_v2, beta_bytes,
        "Alpha con la v2 debe tener el mismo artefacto que Beta"
    );

    // SN 9: último evento ajeno; el ledger queda con anclas en SN 4, 6
    // y 8, a distinta profundidad desde la punta.
    emit_fact(&node1.api, governance_id.clone(), member_fact("Extra5"), true)
        .await
        .unwrap();
    get_subject(&node1.api, governance_id.clone(), Some(9), true)
        .await
        .unwrap();

    // Apagado limpio y borrado selectivo de las filas del
    // ContractRegister de esta gobernanza en la base de datos local.
    node1.token.cancel();
    join_all(node1.handler.iter_mut()).await;

    wipe_contract_register_tables(
        &node1_local.path().join("database.db"),
        &governance_id.to_string(),
    );

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
        ledger_batch_size: Some(4),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node1.api).await.unwrap();

    // La gobernanza arranca en su SN con los tres schemas intactos.
    let gov_state = get_subject(&node1.api, governance_id.clone(), Some(9), true)
        .await
        .unwrap();
    let gov = governance_properties(gov_state.properties);
    for schema_id in ["Alpha", "Beta", "Gamma"] {
        assert!(
            gov.schemas
                .contains_key(&SchemaType::Type(schema_id.to_owned())),
            "el schema {schema_id} debe seguir en la gobernanza"
        );
    }

    // Los artefactos en disco sobreviven byte a byte: el arranque
    // re-deriva las anclas del ledger, verifica los bytes contra ellas
    // y re-registra la metadata sin tocar el artefacto.
    wait_artifact_bytes_eq(node1_contracts.path(), &alpha_name, &alpha_v2)
        .await;
    wait_artifact_bytes_eq(node1_contracts.path(), &beta_name, &beta_bytes)
        .await;
    wait_artifact_bytes_eq(node1_contracts.path(), &gamma_name, &gamma_bytes)
        .await;

    // Y los tres schemas evalúan con los artefactos re-anclados: un
    // subject y un fact commiteado por schema.
    for schema_id in ["Alpha", "Beta", "Gamma"] {
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
            json!({"ModOne": {"data": 5}}),
            true,
        )
        .await
        .unwrap();

        let state = get_subject(&node1.api, subject_id, Some(1), true)
            .await
            .unwrap();
        assert_eq!(
            state.properties,
            json!({"one": 5, "two": 0, "three": 0})
        );
    }

    node_running(&node1.api).await.unwrap();
}


#[test(tokio::test)]
// Muerte de un peer a mitad de descarga: el primer `CanServe`
// (AveNode2) gana el probe pero su `ArtifactRes` se pierde en la red
// (Drop outbound de una ocurrencia) → el requester agota el timeout de
// descarga (5 s en tests), quema al peer para lo que queda de ronda y
// hace failover al segundo `CanServe` (el Owner), que sirve los bytes
// anclados. Escenario determinista: un Hold inbound de la
// `ArtifactProbeRes` del Owner en AveNode3 deja a AveNode2 ganar el
// probe; al liberarla entra como candidato de failover. Pines:
// `downloads_started == 2` (intento muerto + failover), los bytes
// persistidos son los anclados y un fact commitea con la evaluación
// del fetcher. Que el peer muerto no se quema para siempre no es
// observable aquí: el burn vive en la ronda en curso y, al completar
// el fetch en el mismo ciclo, no hay re-sondeo posterior que lo
// muestre.
async fn test_fetch_mid_download_drop_fails_over_to_second_server() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();
    let node3_pk = PublicKey::from_str(node3.api.public_key()).unwrap();

    // SN 1: AveNode2 pasa a ser compiler de la gobernanza (con el Owner
    // son dos compilers sirviendo el mismo artefacto).
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

    // SN 2: alta del schema Example. Los dos compilers compilan la v1;
    // AveNode3 es el ÚNICO evaluador del schema (sin plan B).
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

    // Ambos compilers tienen la v1 promovida antes de que AveNode3
    // sondee (su gate de serving exige el artefacto registrado).
    let artifact_name = format!("{governance_id}_Example");
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // AveNode3: retiene la respuesta de probe del Owner → AveNode2 gana
    // el probe (primer `CanServe`).
    node3
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    // AveNode2: su respuesta de artefacto se pierde en la red → la
    // descarga muere por timeout.
    node2
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: Some(node3_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Drop,
        })
        .await
        .unwrap();

    // AveNode3 aplica SN 2: arranca el fetch de la v1 (batch con los 2
    // compilers, nonce de probe 0).
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // AveNode2 ganó el probe y la descarga desde él ya empezó.
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.downloads_started == 1 && obs.phase == Some("fetch")
    })
    .await;
    assert_eq!(obs.probes_sent, 2);

    // La respuesta de AveNode2 se pierde: nada llega ni se persiste.
    assert!(
        !artifact_dir_exists(node3_contracts.path(), &artifact_name),
        "una descarga que no llega no puede persistir nada"
    );

    // La respuesta retenida del Owner llega tarde: entra en `can_serve`
    // como candidato de failover.
    assert_eq!(node3.api.test_release_held().await.unwrap(), 1);

    // El timeout de descarga (5 s) quema a AveNode2 para la ronda y el
    // failover al Owner completa el fetch con los bytes anclados.
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.downloads_started, 2);
    assert_eq!(obs.probes_sent, 2);
    assert_eq!(obs.cycles_exhausted, 0);

    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // AveNode3 evalúa con el artefacto fetcheado: un fact commitea con
    // su visto bueno.
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
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node3.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}

#[test(tokio::test)]
// Payload comprimido corrupto en tránsito: el primer `CanServe`
// (AveNode2) sirve una `ArtifactRes` cuyo payload zstd viaja
// reemplazado por basura (fault `CorruptCompressed` outbound de una
// ocurrencia). El receptor lo descarta ANTES de hashear — la
// descompresión es el primer paso del registro del artefacto, muy
// antes de tocar disco — quema al peer para la ronda y hace failover
// al segundo `CanServe` (el Owner). Pines: el descarte no persiste
// nada (el directorio del artefacto no existe ni tras el failover,
// comprobado con la respuesta sana retenida), `downloads_started ==
// 2`, los bytes finales son los anclados y un fact commitea. Misma
// mecánica determinista que el test del Drop mid-download: Hold
// inbound de la `ArtifactProbeRes` del Owner para que AveNode2 gane el
// probe.
async fn test_fetch_corrupt_compressed_fails_over_without_persisting() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api],
    )
    .await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();
    let node3_pk = PublicKey::from_str(node3.api.public_key()).unwrap();

    // SN 1: AveNode2 pasa a ser compiler de la gobernanza (con el Owner
    // son dos compilers sirviendo el mismo artefacto).
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

    // SN 2: alta del schema Example. AveNode3 es el ÚNICO evaluador del
    // schema (sin plan B).
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
    let node1_v1 =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    wait_artifact_bytes(node2_contracts.path(), &artifact_name).await;

    // AveNode3: retiene la respuesta de probe del Owner → AveNode2 gana
    // el probe.
    node3
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    // AveNode2: su primera respuesta de artefacto viaja con el payload
    // comprimido corrupto → la descompresión del receptor falla.
    node2
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: Some(node3_pk.clone()),
            remaining: Some(1),
            action: FaultAction::CorruptCompressed,
        })
        .await
        .unwrap();
    // Owner: retiene su respuesta de artefacto → tras el failover nada
    // se persiste hasta que el test la libera.
    node1
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: Some(node3_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // AveNode3 aplica SN 2: arranca el fetch de la v1.
    node3
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node3.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // AveNode2 ganó el probe y la descarga desde él ya empezó.
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.downloads_started == 1 && obs.phase == Some("fetch")
    })
    .await;
    assert_eq!(obs.probes_sent, 2);

    // La respuesta retenida del Owner entra como candidato de failover.
    assert_eq!(node3.api.test_release_held().await.unwrap(), 1);

    // El payload corrupto se descarta al fallar la descompresión (antes
    // de hashear) y el failover al Owner arranca de inmediato — con la
    // respuesta sana aún retenida, el directorio del artefacto sigue sin
    // existir: el descarte no persistió nada.
    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.downloads_started == 2 && obs.phase == Some("fetch")
    })
    .await;
    assert_eq!(obs.probes_sent, 2);
    assert_eq!(obs.cycles_exhausted, 0);
    assert!(
        !artifact_dir_exists(node3_contracts.path(), &artifact_name),
        "el payload que no descomprime se descarta sin tocar disco"
    );

    // Liberada la respuesta sana del Owner, el fetch completa con los
    // bytes anclados.
    assert_eq!(node1.api.test_release_held().await.unwrap(), 1);

    let obs = wait_fetch_obs(&node3.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.downloads_started, 2);
    assert_eq!(obs.probes_sent, 2);
    assert_eq!(obs.cycles_exhausted, 0);

    wait_artifact_bytes_eq(node3_contracts.path(), &artifact_name, &node1_v1)
        .await;

    // AveNode3 evalúa con el artefacto fetcheado: un fact commitea con
    // su visto bueno.
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
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();

    let state = get_subject(&node3.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
    node_running(&node3.api).await.unwrap();
}


#[test(tokio::test)]
// Batching de probes de 3 con todos los servidores mudos: cuatro
// compilers (Owner + AveNode2/3/4) sirven el MISMO artefacto y un
// quinto nodo, único evaluador del schema (sin plan B), fetchea. Un
// Drop outbound de la `ArtifactProbeRes` de cada compiler hacia el
// requester (una ocurrencia por servidor: en el primer ciclo cada uno
// se sondea exactamente una vez) deja el ciclo 1 sordo: primer batch
// de 3 probes (`probes_sent == 3`, `downloads_started == 0`), segundo
// batch de 1 (`probes_sent == 4`), ambos agotan su timeout de 2 s sin
// respuesta y el ciclo se agota (`cycles_exhausted == 1`, timeoff). El
// orden de los batches es aleatorio — por eso se silencian los CUATRO
// servidores: el escenario es determinista igualmente. En el ciclo 2
// (faults ya consumidos, timeoff de 1 s) el primer batch vuelve a
// sondear a 3, el primer `CanServe` gana y el fetch completa
// (`probes_sent == 7`, `downloads_started == 1`) con los bytes
// anclados, y un fact commitea con la evaluación del fetcher. Que un
// batch mudo no consume presupuesto de busy es interno de la máquina
// de estados, no observable desde la Api: el pin observable es la
// secuencia de contadores y la recuperación en el ciclo siguiente.
async fn test_fetch_dead_probe_batches_exhaust_cycle_then_complete() {
    let node1_contracts = tempfile::tempdir().unwrap();
    let node2_contracts = tempfile::tempdir().unwrap();
    let node3_contracts = tempfile::tempdir().unwrap();
    let node4_contracts = tempfile::tempdir().unwrap();
    let node5_contracts = tempfile::tempdir().unwrap();

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

    let mut extra = Vec::new();
    for contracts in [
        &node2_contracts,
        &node3_contracts,
        &node4_contracts,
        &node5_contracts,
    ] {
        let (node, _dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: make_addr(),
            peers: vec![RoutingNode {
                peer_id: node1.api.peer_id().to_string(),
                address: vec![node1.listen_address.clone()],
            }],
            contracts_path: Some(contracts.path().to_path_buf()),
            always_accept: true,
            ..Default::default()
        })
        .await;
        node_running(&node.api).await.unwrap();
        extra.push((node, _dirs));
    }
    let node2 = &extra[0].0;
    let node3 = &extra[1].0;
    let node4 = &extra[2].0;
    let node5 = &extra[3].0;

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api, &node4.api, &node5.api],
    )
    .await;

    let node5_pk = PublicKey::from_str(node5.api.public_key()).unwrap();

    // SN 1: AveNode2, AveNode3 y AveNode4 pasan a ser compilers de la
    // gobernanza (con el Owner son cuatro compilers).
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
                },
                {
                    "name": "AveNode5",
                    "key": node5.api.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "compiler": ["AveNode2", "AveNode3", "AveNode4"]
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

    for node in [node2, node3, node4] {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    // SN 2: alta del schema Example. Los cuatro compilers compilan la
    // v1; AveNode5 es el ÚNICO evaluador del schema (sin plan B).
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
                                "name": "AveNode5",
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
                                "name": "AveNode5",
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

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    for node in [node2, node3, node4] {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    // Los cuatro compilers tienen la v1 promovida antes de que AveNode5
    // sondee (su gate de serving exige el artefacto registrado).
    let artifact_name = format!("{governance_id}_Example");
    let anchored =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    for contracts in [&node2_contracts, &node3_contracts, &node4_contracts] {
        wait_artifact_bytes(contracts.path(), &artifact_name).await;
    }

    // Los cuatro compilers mudos para el primer ciclo: su respuesta de
    // probe hacia AveNode5 se pierde (una ocurrencia cada uno).
    for node in [&node1, node2, node3, node4] {
        node.api
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message: FaultMessage::ArtifactProbeRes,
                peer: Some(node5_pk.clone()),
                remaining: Some(1),
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // AveNode5 aplica SN 2: arranca el fetch de la v1.
    node5
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node5.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Ciclo 1, primer batch: 3 probes a 3 de los 4 compilers (elegidos
    // al azar), todos mudos.
    let obs = wait_fetch_obs(&node5.api, &artifact_name, |obs| {
        obs.probes_sent == 3 && obs.phase == Some("probe")
    })
    .await;
    assert_eq!(obs.downloads_started, 0);

    // Ciclo 1, segundo batch: el cuarto compiler, también mudo.
    let obs = wait_fetch_obs(&node5.api, &artifact_name, |obs| {
        obs.probes_sent == 4
    })
    .await;
    assert_eq!(obs.downloads_started, 0);

    // Sin `CanServe` ni busy: el ciclo se agota y entra en timeoff.
    wait_fetch_obs(&node5.api, &artifact_name, |obs| {
        obs.cycles_exhausted == 1 && obs.phase == Some("timeoff")
    })
    .await;

    // Ciclo 2 (faults consumidos): un batch de 3 probes más, el primer
    // `CanServe` gana y el fetch completa.
    let obs = wait_fetch_obs(&node5.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.probes_sent, 7);
    assert_eq!(obs.downloads_started, 1);
    assert_eq!(obs.cycles_exhausted, 1);

    wait_artifact_bytes_eq(node5_contracts.path(), &artifact_name, &anchored)
        .await;

    // AveNode5 evalúa con el artefacto fetcheado: un fact commitea con
    // su visto bueno.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node5.api, subject_id.clone(), Some(0), true)
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

    let state = get_subject(&node5.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    for (node, _) in &extra {
        node_running(&node.api).await.unwrap();
    }
}

#[test(tokio::test)]
// Respuesta `Busy` al probe con un ÚNICO servidor posible (así el
// "mismo peer" se pinea por construcción): el Owner es el único
// compiler y AveNode2 el único evaluador del schema (sin plan B). El
// requester sondea (nonce 0) y el test inyecta un `Busy` como si
// viniera del Owner — la respuesta real está retenida inbound para que
// no se adelante —; el requester entra en `busy_wait`, espera el
// backoff (1 s en tests) y RE-sondea al mismo peer (nonce 1): la
// respuesta real ya pasa (la regla Hold se consumió con la primera) y
// el fetch completa. Pines: `probes_sent == 2` (probe + re-sondeo),
// `downloads_started == 1`, `cycles_exhausted == 0` (el busy no agota
// el ciclo), bytes anclados y un fact commitea. El `CanServe` retenido
// (nonce 0) queda obsoleto: al liberarlo tras completar se descarta
// como respuesta vieja.
async fn test_fetch_busy_probe_waits_and_reprobes_same_peer() {
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
        contracts_path: Some(node2_contracts.path().to_path_buf()),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node1.api, vec![&node2.api]).await;

    let node1_pk = PublicKey::from_str(node1.api.public_key()).unwrap();
    let node2_pk = PublicKey::from_str(node2.api.public_key()).unwrap();

    // SN 1: alta del schema Example con AveNode2 como ÚNICO evaluador.
    // El Owner es el único compiler de la gobernanza: único servidor
    // posible del artefacto.
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

    emit_fact(&node1.api, governance_id.clone(), json, true)
        .await
        .unwrap();

    get_subject(&node1.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let artifact_name = format!("{governance_id}_Example");
    let anchored =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;

    // AveNode2: retiene la respuesta de probe real del Owner → el
    // `Busy` inyectado no compite con ella.
    node2
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::ArtifactProbeRes,
            peer: Some(node1_pk.clone()),
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // AveNode2 aplica SN 1: arranca el fetch (probe al Owner, nonce 0).
    node2
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node2.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let obs = wait_fetch_obs(&node2.api, &artifact_name, |obs| {
        obs.probes_sent == 1 && obs.phase == Some("probe")
    })
    .await;
    assert_eq!(obs.downloads_started, 0);

    // El Owner responde `Busy` al probe (está compilando): el requester
    // no quema al peer ni agota el ciclo — espera para re-sondearlo.
    // Los mensajes de artefacto no van firmados: el intermediario los
    // entrega al contract compiler con el sender de la clave indicada.
    node2
        .api
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver: node2_pk.clone(),
                    receiver_actor: format!(
                        "/user/node/subject_manager/{governance_id}/Example_contract_compiler"
                    ),
                },
                message: ActorMessage::ArtifactProbeRes {
                    request_nonce: 0,
                    result: ArtifactProbeResult::Busy,
                },
            },
            &node1_pk,
        )
        .await
        .unwrap();

    // Espera de busy: ni descarga ni ciclo agotado.
    let obs = wait_fetch_obs(&node2.api, &artifact_name, |obs| {
        obs.phase == Some("busy_wait")
    })
    .await;
    assert_eq!(obs.downloads_started, 0);
    assert_eq!(obs.cycles_exhausted, 0);

    // Tras el backoff (1 s) re-sondea al MISMO peer; la respuesta real
    // ya pasa y el fetch completa sin agotar el ciclo.
    let obs = wait_fetch_obs(&node2.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.probes_sent, 2);
    assert_eq!(obs.downloads_started, 1);
    assert_eq!(obs.cycles_exhausted, 0);

    wait_artifact_bytes_eq(node2_contracts.path(), &artifact_name, &anchored)
        .await;

    // El `CanServe` retenido (nonce 0) llega tarde: se descarta como
    // respuesta vieja, el fetch ya terminó.
    assert_eq!(node2.api.test_release_held().await.unwrap(), 1);

    // AveNode2 evalúa con el artefacto fetcheado: un fact commitea con
    // su visto bueno.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node2.api, subject_id.clone(), Some(0), true)
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

    let state = get_subject(&node2.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    node_running(&node2.api).await.unwrap();
}

#[test(tokio::test)]
// Un artefacto basta: tres compilers (Owner + AveNode2/3) sirviendo el
// MISMO artefacto y un cuarto nodo, único evaluador del schema, que
// fetchea. El primer `CanServe` del batch (los 3 compilers caben en un
// único batch de probes) gana la descarga y los `CanServe` del resto
// solo engrosan la lista de failover: nunca hay descargas paralelas.
// Pines: `probes_sent == 3` (un solo batch), `downloads_started == 1`,
// `cycles_exhausted == 0`, bytes anclados y un fact commitea.
async fn test_fetch_single_download_with_all_servers_serving() {
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

    let mut extra = Vec::new();
    for contracts in [&node2_contracts, &node3_contracts, &node4_contracts]
    {
        let (node, _dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: make_addr(),
            peers: vec![RoutingNode {
                peer_id: node1.api.peer_id().to_string(),
                address: vec![node1.listen_address.clone()],
            }],
            contracts_path: Some(contracts.path().to_path_buf()),
            always_accept: true,
            ..Default::default()
        })
        .await;
        node_running(&node.api).await.unwrap();
        extra.push((node, _dirs));
    }
    let node2 = &extra[0].0;
    let node3 = &extra[1].0;
    let node4 = &extra[2].0;

    let governance_id = create_and_authorize_governance(
        &node1.api,
        vec![&node2.api, &node3.api, &node4.api],
    )
    .await;

    // SN 1: AveNode2 y AveNode3 pasan a ser compilers de la gobernanza
    // (con el Owner son tres compilers).
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
                    "compiler": ["AveNode2", "AveNode3"]
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

    for node in [node2, node3] {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    // SN 2: alta del schema Example. Los tres compilers compilan la v1;
    // AveNode4 es el ÚNICO evaluador del schema (sin plan B).
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
                                "name": "AveNode4",
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

    get_subject(&node1.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    for node in [node2, node3] {
        node.api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(&node.api, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    }

    // Los tres compilers tienen la v1 promovida antes de que AveNode4
    // sondee.
    let artifact_name = format!("{governance_id}_Example");
    let anchored =
        wait_artifact_bytes(node1_contracts.path(), &artifact_name).await;
    for contracts in [&node2_contracts, &node3_contracts] {
        wait_artifact_bytes(contracts.path(), &artifact_name).await;
    }

    // AveNode4 aplica SN 2: arranca el fetch de la v1 (un único batch
    // de probes a los 3 compilers).
    node4
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&node4.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // El primer `CanServe` gana y basta: una sola descarga.
    let obs = wait_fetch_obs(&node4.api, &artifact_name, |obs| {
        obs.phase == Some("done")
    })
    .await;
    assert_eq!(obs.probes_sent, 3);
    assert_eq!(obs.downloads_started, 1);
    assert_eq!(obs.cycles_exhausted, 0);

    wait_artifact_bytes_eq(node4_contracts.path(), &artifact_name, &anchored)
        .await;

    // AveNode4 evalúa con el artefacto fetcheado: un fact commitea con
    // su visto bueno.
    let (subject_id, ..) =
        create_subject(&node1.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    get_subject(&node4.api, subject_id.clone(), Some(0), true)
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

    let state = get_subject(&node4.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 7, "two": 0, "three": 0}));

    for (node, _) in &extra {
        node_running(&node.api).await.unwrap();
    }
}
