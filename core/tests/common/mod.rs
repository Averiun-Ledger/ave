use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    bridge::request::ApprovalStateRes,
    identity::{
        DigestIdentifier, HashAlgorithm, KeyPairAlgorithm, PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
    request::{
        ConfirmRequest, CreateRequest, EventRequest, FactRequest,
        RejectRequest, TransferRequest,
    },
    response::{MonitorNetworkState, PaginatorAborts, RequestState, SubjectDB},
};
use ave_core::{
    Api,
    config::{
        AveExternalDBConfig, AveExternalDBFeatureConfig, AveInternalDBConfig,
        AveInternalDBFeatureConfig, Config, SinkAuth,
    },
};
use network::{Config as NetworkConfig, RoutingNode};
use std::{
    str::FromStr,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub static PORT_COUNTER: AtomicU16 = AtomicU16::new(45000);

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

pub async fn create_node(
    node_type: network::NodeType,
    listen_address: &str,
    peers: Vec<RoutingNode>,
    always_accept: bool,
    keys: Option<KeyPair>,
) -> (NodeData, Vec<TempDir>) {
    let keys =
        keys.unwrap_or(KeyPair::Ed25519(Ed25519Signer::generate().unwrap()));

    let mut vec_dirs = vec![];
    let dir = tempfile::tempdir().expect("Can not create temporal directory");
    let local_db = dir.path().to_path_buf();
    vec_dirs.push(dir);

    let dir = tempfile::tempdir().expect("Can not create temporal directory");
    let ext_db = dir.path().to_path_buf();
    vec_dirs.push(dir);

    let network_config = NetworkConfig::new(
        node_type,
        vec![listen_address.to_owned()],
        vec![],
        peers,
    );

    let contract_dir =
        tempfile::tempdir().expect("Can not create temporal directory");
    let contracts_path = contract_dir.path().to_path_buf();
    vec_dirs.push(contract_dir);

    let config = Config {
        is_service: true,
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
        always_accept,
        tracking_size: 100,
        spec: None,
    };

    let token = CancellationToken::new();

    let (api, runners) =
        Api::build(keys.clone(), config, SinkAuth::default(), "ave", &token)
            .await
            .unwrap();

    (
        NodeData {
            api,
            handler: runners,
            token,
            keys,
            listen_address: listen_address.to_owned(),
        },
        vec_dirs,
    )
}

pub async fn create_nodes_and_connections(
    bootstrap: Vec<Vec<usize>>,
    addressable: Vec<Vec<usize>>,
    ephemeral: Vec<Vec<usize>>,
    always_accept: bool,
) -> (Vec<NodeData>, Vec<TempDir>) {
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

        let (node, .., mut vec_dirs) = create_node(
            network::NodeType::Bootstrap,
            &listen_address,
            peers,
            always_accept,
            None,
        )
        .await;
        dirs.append(&mut vec_dirs);

        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }

    tokio::time::sleep(Duration::from_secs(5)).await;

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

        let (node, .., mut vec_dirs) = create_node(
            network::NodeType::Addressable,
            &listen_address,
            peers,
            always_accept,
            None,
        )
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

        let (node, .., mut vec_dirs) = create_node(
            network::NodeType::Ephemeral,
            &listen_address,
            peers,
            always_accept,
            None,
        )
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

pub async fn get_subject(
    node: &Api,
    subject_id: DigestIdentifier,
    sn: Option<u64>,
) -> Result<SubjectDB, Box<dyn std::error::Error>> {
    loop {
        if let Ok(state) = node.get_subject_state(subject_id.clone()).await {
            if let Some(sn) = sn {
                if sn == state.sn {
                    return Ok(state);
                }
            } else {
                return Ok(state);
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
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
                Some(request_id.clone()),
                None,
                None,
                None,
                None,
            )
            .await
        {
            return Ok(state);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
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
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            } else {
                return Ok(state.state);
            }
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await;
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
        tokio::time::sleep(Duration::from_secs(1)).await;
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
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}

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
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}

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
