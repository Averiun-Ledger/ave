use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    bridge::request::{AbortsQuery, ApprovalStateRes, EventsQuery},
    identity::{
        DigestIdentifier, HashAlgorithm, KeyPairAlgorithm, PublicKey,
        Signature, Signed,
        keys::{Ed25519Signer, KeyPair},
    },
    request::{
        ConfirmRequest, CreateRequest, EOLRequest, EventRequest, FactRequest,
        RejectRequest, TransferRequest,
    },
    response::{LedgerDB, MonitorNetworkState, PaginatorAborts, RequestEventDB, RequestState, SubjectDB},
};
use ave_core::{
    Api,
    config::{
        AveExternalDBConfig, AveExternalDBFeatureConfig, AveInternalDBConfig,
        AveInternalDBFeatureConfig, Config, GovernanceSyncConfig,
        RebootSyncConfig, SinkAuth, SyncConfig, TrackerSyncConfig,
        UpdateSyncConfig,
    },
};
use network::{Config as NetworkConfig, RoutingNode};
use prometheus_client::registry::Registry;
use std::{
    collections::BTreeSet, env, fs, path::PathBuf, process, str::FromStr, sync::atomic::{AtomicU16, AtomicU64, Ordering}, time::Duration
};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub static PORT_COUNTER: AtomicU16 = AtomicU16::new(45000);
pub static CONTRACTS_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct NodeData {
    pub api: Api,
    #[allow(dead_code)]
    pub handler: Vec<JoinHandle<()>>,
    #[allow(dead_code)]
    pub token: CancellationToken,
    #[allow(dead_code)]
    pub keys: KeyPair,
    #[allow(dead_code)]
    pub listen_address: String,
}

#[derive(Default)]
pub struct CreateNodesAndConnectionsConfig {
    pub bootstrap: Vec<Vec<usize>>,
    pub addressable: Vec<Vec<usize>>,
    pub ephemeral: Vec<Vec<usize>>,
    pub always_accept: bool,
    pub is_service: bool,
    pub ledger_batch_size: Option<usize>,
}

#[derive(Default)]
pub struct CreateNodeConfig {
    pub node_type: network::NodeType,
    pub listen_address: String,
    pub peers: Vec<RoutingNode>,
    pub always_accept: bool,
    pub is_service: bool,
    pub keys: Option<KeyPair>,
    pub local_db: Option<PathBuf>,
    pub ext_db: Option<PathBuf>,
    pub ledger_batch_size: Option<usize>,
}

pub async fn create_node(
    config: CreateNodeConfig,
) -> (NodeData, Vec<TempDir>) {
    let CreateNodeConfig {
        node_type,
        listen_address,
        peers,
        always_accept,
        is_service,
        keys,
        local_db,
        ext_db,
        ledger_batch_size,
    } = config;

    let keys =
        keys.unwrap_or(KeyPair::Ed25519(Ed25519Signer::generate().unwrap()));

    let mut vec_dirs = vec![];
    let local_db = if let Some(local_db) = local_db {
        local_db
    } else {
        let dir =
            tempfile::tempdir().expect("Can not create temporal directory");
        let local_db = dir.path().to_path_buf();
        vec_dirs.push(dir);

        local_db
    };

    let ext_db = if let Some(ext_db) = ext_db {
        ext_db
    } else {
        let dir =
            tempfile::tempdir().expect("Can not create temporal directory");
        let ext_db = dir.path().to_path_buf();
        vec_dirs.push(dir);

        ext_db
    };

    let network_config = NetworkConfig::new(
        node_type,
        vec![listen_address.clone()],
        vec![],
        peers,
    );

    let contracts_path = env::temp_dir().join(format!(
        "ave-test-contracts-{}-{}",
        process::id(),
        CONTRACTS_COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir_all(&contracts_path)
        .expect("Can not create contracts directory");

    let config = Config {
        is_service,
        keypair_algorithm: KeyPairAlgorithm::Ed25519,
        hash_algorithm: HashAlgorithm::Blake3,
        internal_db: AveInternalDBConfig {
            db: AveInternalDBFeatureConfig::build(&local_db),
            ..Default::default()
        },
        external_db: AveExternalDBConfig {
            db: AveExternalDBFeatureConfig::build(&ext_db),
            ..Default::default()
        },
        network: network_config,
        contracts_path,
        safe_mode: false,
        always_accept,
        tracking_size: 100,
        sync: SyncConfig {
            ledger_batch_size: ledger_batch_size.unwrap_or(100),
            governance: GovernanceSyncConfig {
                interval_secs: 10,
                sample_size: 3,
                response_timeout_secs: 5,
            },
            tracker: TrackerSyncConfig {
                interval_secs: 10,
                page_size: 10,
                response_timeout_secs: 5,
                update_batch_size: 2,
                update_timeout_secs: 5,
            },
            update: UpdateSyncConfig::default(),
            reboot: RebootSyncConfig::default(),
        },
        spec: None,
    };

    let crash_token = CancellationToken::new();
    let graceful_token = CancellationToken::new();
    let mut registry = Registry::default();

    let (api, runners) = Api::build(
        keys.clone(),
        config,
        SinkAuth::default(),
        &mut registry,
        "ave",
        graceful_token.clone(),
        crash_token,
    )
    .await
    .unwrap();

    (
        NodeData {
            api,
            handler: runners,
            token: graceful_token,
            keys,
            listen_address,
        },
        vec_dirs,
    )
}

pub async fn create_nodes_and_connections(
    config: CreateNodesAndConnectionsConfig,
) -> (Vec<NodeData>, Vec<TempDir>) {
    let CreateNodesAndConnectionsConfig {
        bootstrap,
        addressable,
        ephemeral,
        always_accept,
        is_service,
        ledger_batch_size,
    } = config;

    let mut nodes: Vec<NodeData> = Vec::new();
    let mut dirs = vec![];

    let mut bootstrap_address = vec![];

    // Create Bootstrap nodes
    for connections in bootstrap.iter() {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let listen_address = format!("/memory/{}", port);

        bootstrap_address.push(listen_address.clone());

        let peers = connections
            .iter()
            .map(|&peer_idx| RoutingNode {
                peer_id: nodes[peer_idx].api.peer_id().to_string(),
                address: vec![bootstrap_address[peer_idx].clone()],
            })
            .collect();

        let (node, .., mut vec_dirs) = create_node(CreateNodeConfig {
            node_type: network::NodeType::Bootstrap,
            listen_address: listen_address.clone(),
            peers,
            always_accept,
            is_service,
            ledger_batch_size,
            ..Default::default()
        })
        .await;
        dirs.append(&mut vec_dirs);

        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }

    for connections in addressable.iter() {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let listen_address = format!("/memory/{}", port);

        let peers = connections
            .iter()
            .map(|&peer_idx| RoutingNode {
                peer_id: nodes[peer_idx].api.peer_id().to_string(),
                address: vec![bootstrap_address[peer_idx].clone()],
            })
            .collect();

        let (node, .., mut vec_dirs) = create_node(CreateNodeConfig {
            node_type: network::NodeType::Addressable,
            listen_address: listen_address.clone(),
            peers,
            always_accept,
            is_service,
            ledger_batch_size,
            ..Default::default()
        })
        .await;
        dirs.append(&mut vec_dirs);

        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }

    for connections in ephemeral.iter() {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let listen_address = format!("/memory/{}", port);

        let peers = connections
            .iter()
            .map(|&peer_idx| RoutingNode {
                peer_id: nodes[peer_idx].api.peer_id().to_string(),
                address: vec![bootstrap_address[peer_idx].clone()],
            })
            .collect();

        let (node, .., mut vec_dirs) = create_node(CreateNodeConfig {
            node_type: network::NodeType::Ephemeral,
            listen_address: listen_address.clone(),
            peers,
            always_accept,
            is_service,
            ledger_batch_size,
            ..Default::default()
        })
        .await;
        dirs.append(&mut vec_dirs);

        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }

    (nodes, dirs)
}

/// Crea una governance en `owner_node` y lo autoriza en `other_nodes`.
/// Retorna el `governance_id` generado.
/// Correcto
pub async fn create_and_authorize_governance(
    owner_node: &Api,
    other_nodes: Vec<&Api>,
) -> DigestIdentifier {
    let request = EventRequest::Create(CreateRequest {
        name: Some("Governance Tests".to_owned()),
        description: Some("A description for Governance Tests".to_owned()),
        governance_id: DigestIdentifier::default(),
        schema_id: SchemaType::Governance,
        namespace: Namespace::new(),
    });
    let data = owner_node.own_request(request).await.unwrap();
    let governance_id = data.subject_id;
    wait_request(owner_node, data.request_id).await.unwrap();

    for node in other_nodes {
        node.auth_subject(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(&owner_node.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    }

    governance_id
}

#[allow(dead_code)]
pub async fn create_subject(
    node: &Api,
    governance_id: DigestIdentifier,
    schema_id: &str,
    namespace: &str,
    wait_request_state: bool,
) -> Result<(DigestIdentifier, DigestIdentifier), Box<dyn std::error::Error>> {
    let request = EventRequest::Create(CreateRequest {
        name: Some("A Subject".to_owned()),
        description: Some("A description for Subject".to_owned()),
        governance_id,
        schema_id: SchemaType::Type(schema_id.to_owned()),
        namespace: Namespace::from(namespace),
    });
    let response = node.own_request(request).await?;
    let subject_id = response.subject_id;

    if !wait_request_state {
        return Ok((subject_id, response.request_id));
    }

    let request_id = response.request_id;
    wait_request(node, request_id.clone()).await.unwrap();

    Ok((subject_id, request_id))
}

pub async fn emit_fact(
    node: &Api,
    subject_id: DigestIdentifier,
    payload_json: serde_json::Value,
    wait_request_state: bool,
) -> Result<DigestIdentifier, Box<dyn std::error::Error>> {
    let request = EventRequest::Fact(FactRequest {
        subject_id,
        payload: ValueWrapper(payload_json),
        viewpoints: Default::default(),
    });

    let response = node.own_request(request).await?;
    // state of request
    let request_id = response.request_id;

    if !wait_request_state {
        return Ok(request_id);
    }

    wait_request(node, request_id.clone()).await.unwrap();

    Ok(request_id)
}

#[allow(dead_code)]
pub async fn emit_fact_viewpoints(
    node: &Api,
    subject_id: DigestIdentifier,
    payload_json: serde_json::Value,
    viewpoints: BTreeSet<String>,
    wait_request_state: bool,
) -> Result<DigestIdentifier, Box<dyn std::error::Error>> {
    let request = EventRequest::Fact(FactRequest {
        subject_id,
        payload: ValueWrapper(payload_json),
        viewpoints,
    });

    let response = node.own_request(request).await?;
    // state of request
    let request_id = response.request_id;

    if !wait_request_state {
        return Ok(request_id);
    }

    wait_request(node, request_id.clone()).await.unwrap();

    Ok(request_id)
}

#[allow(dead_code)]
pub fn assert_tracker_fact_full(
    event: &RequestEventDB,
    expected_payload: serde_json::Value,
    expected_viewpoints: &[&str],
) {
    match event {
        RequestEventDB::TrackerFactFull {
            payload,
            viewpoints,
            ..
        } => {
            assert_eq!(payload, &expected_payload);
            assert_eq!(
                viewpoints,
                &expected_viewpoints
                    .iter()
                    .map(|viewpoint| viewpoint.to_string())
                    .collect::<Vec<_>>()
            );
        }
        event => panic!("unexpected fact event: {event:?}"),
    }
}

#[allow(dead_code)]
pub async fn emit_fact_signed(
    node: &Api,
    keys: &KeyPair,
    subject_id: DigestIdentifier,
    payload_json: serde_json::Value,
    wait_request_state: bool,
) -> Result<DigestIdentifier, Box<dyn std::error::Error>> {
    let request = EventRequest::Fact(FactRequest {
        subject_id,
        payload: ValueWrapper(payload_json),
        viewpoints: Default::default(),
    });

    let signature = Signature::new(&request, keys).unwrap();
    let signed_event = Signed::from_parts(request, signature);

    let response = node.external_request(signed_event).await?;
    // state of request
    let request_id = response.request_id;

    if !wait_request_state {
        return Ok(request_id);
    }

    wait_request(node, request_id.clone()).await.unwrap();

    Ok(request_id)
}

pub async fn get_subject(
    node: &Api,
    subject_id: DigestIdentifier,
    sn: Option<u64>,
    timeout: bool,
) -> Result<SubjectDB, Box<dyn std::error::Error>> {
    let mut count = 0;
    loop {
        if let Ok(state) = node.get_subject_state(subject_id.clone()).await {
            if let Some(sn) = sn {
                if sn == state.sn {
                    return Ok(state);
                } else if count > 100 {
                    return Err(format!(
                        "timeout waiting for subject {} at sn {}, actual sn {}",
                        subject_id, sn, state.sn
                    )
                    .into());
                }
            } else {
                return Ok(state);
            }
        } else if count > 100 {
            return Err(format!(
                "timeout waiting for subject {} at sn {:?}",
                subject_id, sn
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        if timeout {
            count += 1;
        }
    }
}

#[allow(dead_code)]
pub async fn get_events(
    node: &Api,
    subject_id: DigestIdentifier,
    expected_len: usize,
    timeout: bool,
) -> Result<Vec<LedgerDB>, Box<dyn std::error::Error>> {
    let mut count = 0;
    loop {
        if let Ok(state) = node
            .get_events(
                subject_id.clone(),
                EventsQuery {
                    quantity: Some(expected_len.max(1000) as u64),
                    page: Some(0),
                    reverse: Some(false),
                    event_request_ts: None,
                    event_ledger_ts: None,
                    sink_ts: None,
                    event_type: None,
                },
            )
            .await
        {
            if state.events.len() == expected_len {
                return Ok(state.events);
            } else if count > 100 {
                return Err(format!(
                    "timeout waiting for events {} at len {}, actual len {}",
                    subject_id,
                    expected_len,
                    state.events.len()
                )
                .into());
            }
        } else if count > 100 {
            return Err(format!(
                "timeout waiting for events {} at len {}",
                subject_id, expected_len
            )
            .into());
        }

        tokio::time::sleep(Duration::from_millis(300)).await;
        if timeout {
            count += 1;
        }
    }
}

#[allow(dead_code)]
pub async fn get_abort_request(
    node: &Api,
    subject_id: DigestIdentifier,
    request_id: DigestIdentifier,
) -> Result<PaginatorAborts, Box<dyn std::error::Error>> {
    loop {
        if let Ok(state) = node
            .get_aborts(
                subject_id.clone(),
                AbortsQuery {
                    request_id: Some(request_id.to_string()),
                    sn: None,
                    quantity: None,
                    page: None,
                    reverse: None,
                },
            )
            .await
        {
            return Ok(state);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

#[allow(dead_code)]
pub async fn wait_request_state(
    node: &Api,
    request_id: DigestIdentifier,
    request_state: Option<RequestState>,
) -> Result<RequestState, Box<dyn std::error::Error>> {
    loop {
        if let Ok(state) = node.get_request_state(request_id.clone()).await {
            if let Some(request_state) = request_state.clone() {
                match (request_state, state.state.clone()) {
                    (RequestState::InQueue, RequestState::InQueue)
                    | (RequestState::Handling, RequestState::Handling)
                    | (
                        RequestState::Invalid { .. },
                        RequestState::Invalid { .. },
                    )
                    | (
                        RequestState::Abort { .. },
                        RequestState::Abort { .. },
                    )
                    | (RequestState::Reboot, RequestState::Reboot)
                    | (
                        RequestState::RebootDiff { .. },
                        RequestState::RebootDiff { .. },
                    )
                    | (
                        RequestState::RebootTimeOut { .. },
                        RequestState::RebootTimeOut { .. },
                    )
                    | (RequestState::Validation, RequestState::Validation)
                    | (
                        RequestState::Distribution,
                        RequestState::Distribution,
                    )
                    | (RequestState::Finish, RequestState::Finish) => {
                        return Ok(state.state);
                    }
                    _ => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                }
            } else {
                return Ok(state.state);
            }
        } else {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

/*
    Abort,
    InQueue,
    Invalid,
    Finish,
    Reboot,
    Evaluation,
    Approval,
    Validation,
    Distribution
*/
pub async fn wait_request(
    node: &Api,
    request_id: DigestIdentifier,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        if let Ok(state) = node.get_request_state(request_id.clone()).await {
            match state.state {
                RequestState::Approval
                | RequestState::Abort { .. }
                | RequestState::Invalid { .. }
                | RequestState::Finish => break,
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Segundo para que la información se escriba en el sumidero
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}

pub async fn node_running(
    node: &Api,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        if let Ok(state) = node.get_network_state().await {
            if let MonitorNetworkState::Running = state {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn emit_transfer(
    node: &Api,
    subject_id: DigestIdentifier,
    new_owner: PublicKey,
    wait_request_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = EventRequest::Transfer(TransferRequest {
        subject_id,
        new_owner,
    });

    let response = node.own_request(request).await?;
    // state of request
    if !wait_request_state {
        return Ok(());
    }

    let request_id = response.request_id;
    wait_request(node, request_id.clone()).await.unwrap();

    Ok(())
}

#[allow(dead_code)]
pub async fn emit_approve(
    node: &Api,
    governance_id: DigestIdentifier,
    res: ApprovalStateRes,
    request_id: DigestIdentifier,
    wait_request_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    node.approve(governance_id.clone(), res).await.unwrap();

    // state of request
    if !wait_request_state {
        return Ok(());
    }

    loop {
        if let Ok(state) = node.get_request_state(request_id.clone()).await {
            match state.state {
                RequestState::Approval
                | RequestState::Abort { .. }
                | RequestState::Invalid { .. }
                | RequestState::Finish => break,
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn emit_confirm(
    node: &Api,
    subject_id: DigestIdentifier,
    new_name: Option<String>,
    wait_request_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = EventRequest::Confirm(ConfirmRequest {
        subject_id,
        name_old_owner: new_name,
    });
    let response = node.own_request(request).await?;
    // state of request
    if !wait_request_state {
        return Ok(());
    }

    let request_id = response.request_id;
    wait_request(node, request_id.clone()).await.unwrap();

    Ok(())
}

#[allow(dead_code)]
pub async fn emit_reject(
    node: &Api,
    subject_id: DigestIdentifier,
    wait_request_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = EventRequest::Reject(RejectRequest { subject_id });
    let response = node.own_request(request).await?;
    // state of request
    if !wait_request_state {
        return Ok(());
    }

    let request_id = response.request_id;
    wait_request(node, request_id.clone()).await.unwrap();

    Ok(())
}

#[allow(dead_code)]
pub async fn emit_eol(
    node: &Api,
    subject_id: DigestIdentifier,
    wait_request_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = EventRequest::EOL(EOLRequest { subject_id });
    let response = node.own_request(request).await?;
    // state of request
    if !wait_request_state {
        return Ok(());
    }

    let request_id = response.request_id;
    wait_request(node, request_id.clone()).await.unwrap();

    Ok(())
}
