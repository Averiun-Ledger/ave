use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    bridge::request::{
        AbortsQuery, ApprovalStateRes, EventsQuery, SinkEventsQuery,
    },
    identity::{
        DigestIdentifier, HashAlgorithm, KeyPairAlgorithm, PublicKey,
        Signature, Signed,
        keys::{Ed25519Signer, KeyPair},
    },
    request::{
        ConfirmRequest, CreateRequest, EOLRequest, EventRequest, FactRequest,
        RejectRequest, TransferRequest,
    },
    response::{
        LedgerDB, MonitorNetworkState, PaginatorAborts, RequestEventDB,
        RequestState, SubjectDB, TrackerEventVisibilityRangeDB,
        TrackerStoredVisibilityRangeDB, TrackerVisibilityModeDB,
    },
    sink::DataToSink,
};
use ave_core::{
    Api,
    config::{
        AveExternalDBConfig, AveExternalDBFeatureConfig, AveInternalDBConfig,
        AveInternalDBFeatureConfig, Config,
        GovernanceSyncConfig, RebootSyncConfig, SinkConfigEntry, SyncConfig,
        TrackerSyncConfig, UpdateSyncConfig,
    },
    governance::data::GovernanceData,
};
#[cfg(feature = "test")]
use ave_core::config::CompilerNodeConfig;
use ave_network::{Config as NetworkConfig, RoutingNode};
use prometheus_client::registry::Registry;
use serde_json::{Value, from_value};
use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs,
    path::PathBuf,
    process,
    str::FromStr,
    sync::atomic::{AtomicU16, AtomicU64, Ordering},
    time::Duration,
};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub static PORT_COUNTER: AtomicU16 = AtomicU16::new(45000);
pub static CONTRACTS_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Helper to set an environment variable for the duration of a test and clean
/// it up afterwards. `std::env::set_var`/`remove_var` are unsafe in Rust 2024
/// because concurrent mutation of the process environment is UB; tests that
/// use distinct variable names and short-lived scopes are safe in practice.
#[allow(dead_code)]
pub struct TempEnvVar {
    name: &'static str,
}

impl TempEnvVar {
    #[allow(dead_code)]
    pub fn set(name: &'static str, value: &str) -> Self {
        unsafe { std::env::set_var(name, value) };
        Self { name }
    }
}

impl Drop for TempEnvVar {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(self.name) };
    }
}

#[allow(dead_code)]
pub mod grpc_test_sink;
#[allow(dead_code)]
pub mod kafka_setup;
#[allow(dead_code)]
pub mod oidc_idp;
pub mod sink_setup;

#[allow(dead_code)]
pub mod test_sink;

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
    pub only_clear_events: bool,
    pub ledger_batch_size: Option<usize>,
}

#[derive(Default)]
pub struct CreateNodeConfig {
    pub node_type: ave_network::NodeType,
    pub listen_address: String,
    pub peers: Vec<RoutingNode>,
    pub always_accept: bool,
    pub is_service: bool,
    pub only_clear_events: bool,
    pub keys: Option<KeyPair>,
    pub local_db: Option<PathBuf>,
    pub ext_db: Option<PathBuf>,
    pub ledger_batch_size: Option<usize>,
    pub safe_mode: bool,
    pub sinks: Vec<SinkConfigEntry>,
    /// Explicit compiler configuration; `None` uses the default (in tests,
    /// the auto-injected embedded compiler). Only exists in test builds:
    /// production nodes compile in-process and have no pool config.
    #[cfg(feature = "test")]
    pub compiler: Option<CompilerNodeConfig>,
    /// Explicit contracts directory; `None` generates a fresh one. Needed
    /// by tests that manipulate the on-disk artifacts (permissions,
    /// deletions) to exercise boot-time failures.
    pub contracts_path: Option<PathBuf>,
}

pub async fn create_node(config: CreateNodeConfig) -> (NodeData, Vec<TempDir>) {
    try_create_node(config).await.unwrap()
}

/// Fallible variant of [`create_node`] for tests that expect the node boot
/// to fail (fatal contract artifact errors surface as `Api::build` errors).
#[allow(dead_code)]
pub async fn try_create_node(
    config: CreateNodeConfig,
) -> Result<(NodeData, Vec<TempDir>), ave_core::error::Error> {
    let CreateNodeConfig {
        node_type,
        listen_address,
        peers,
        always_accept,
        is_service,
        only_clear_events,
        keys,
        local_db,
        ext_db,
        ledger_batch_size,
        safe_mode,
        sinks,
        #[cfg(feature = "test")]
        compiler,
        contracts_path,
    } = config;

    let keys =
        keys.unwrap_or(KeyPair::Ed25519(Ed25519Signer::generate().unwrap()));

    let mut vec_dirs = vec![];
    let local_db = local_db.unwrap_or_else(|| {
        let dir =
            tempfile::tempdir().expect("Can not create temporal directory");
        let local_db = dir.path().to_path_buf();
        vec_dirs.push(dir);

        local_db
    });

    let ext_db = ext_db.unwrap_or_else(|| {
        let dir =
            tempfile::tempdir().expect("Can not create temporal directory");
        let ext_db = dir.path().to_path_buf();
        vec_dirs.push(dir);

        ext_db
    });

    let network_config = NetworkConfig::new(
        node_type,
        vec![listen_address.clone()],
        vec![],
        peers,
    );

    let contracts_path = contracts_path.unwrap_or_else(|| {
        env::temp_dir().join(format!(
            "ave-test-contracts-{}-{}",
            process::id(),
            CONTRACTS_COUNTER.fetch_add(1, Ordering::SeqCst)
        ))
    });
    fs::create_dir_all(&contracts_path)
        .expect("Can not create contracts directory");

    let config = Config {
        is_service,
        only_clear_events,
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
        safe_mode,
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
        // The field only exists in test builds (production nodes
        // compile in-process and have no compiler pool config).
        #[cfg(feature = "test")]
        compiler: compiler.unwrap_or_default(),
        spec: None,
    };

    let crash_token = CancellationToken::new();
    let graceful_token = CancellationToken::new();
    let mut registry = Registry::default();

    let (api, runners) = Api::build(
        keys.clone(),
        config,
        sinks,
        &mut registry,
        "ave",
        graceful_token.clone(),
        crash_token,
    )
    .await?;

    Ok((
        NodeData {
            api,
            handler: runners,
            token: graceful_token,
            keys,
            listen_address,
        },
        vec_dirs,
    ))
}

#[allow(dead_code)]
pub async fn create_nodes_and_connections(
    config: CreateNodesAndConnectionsConfig,
) -> (Vec<NodeData>, Vec<TempDir>) {
    let CreateNodesAndConnectionsConfig {
        bootstrap,
        addressable,
        ephemeral,
        always_accept,
        is_service,
        only_clear_events,
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
            node_type: ave_network::NodeType::Bootstrap,
            listen_address: listen_address.clone(),
            peers,
            always_accept,
            is_service,
            only_clear_events,
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
            node_type: ave_network::NodeType::Addressable,
            listen_address: listen_address.clone(),
            peers,
            always_accept,
            is_service,
            only_clear_events,
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
            node_type: ave_network::NodeType::Ephemeral,
            listen_address: listen_address.clone(),
            peers,
            always_accept,
            is_service,
            only_clear_events,
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
#[allow(dead_code)]
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
        node.authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner_node.public_key()).unwrap(),
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
                    ..Default::default()
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
                    | (RequestState::Evaluation, RequestState::Evaluation)
                    | (RequestState::Approval, RequestState::Approval)
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

#[allow(dead_code)]
pub async fn node_running(
    node: &Api,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        if let Ok(state) = node.get_network_state().await
            && state == MonitorNetworkState::Running
        {
            break;
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

#[allow(dead_code)]
pub fn assert_tracker_fact_opaque(
    event: &RequestEventDB,
    expected_viewpoints: &[&str],
) -> Result<(), String> {
    match event {
        RequestEventDB::TrackerFactOpaque { viewpoints, .. } => {
            let expected = expected_viewpoints
                .iter()
                .map(|viewpoint| viewpoint.to_string())
                .collect::<Vec<_>>();
            if viewpoints != &expected {
                return Err(format!(
                    "unexpected opaque viewpoints: got {:?}, expected {:?}",
                    viewpoints, expected
                ));
            }
            Ok(())
        }
        event => Err(format!("unexpected opaque fact event: {event:?}")),
    }
}

#[allow(dead_code)]
pub fn assert_tracker_visibility(
    state: &SubjectDB,
    expected_mode: TrackerVisibilityModeDB,
    expected_stored: Vec<TrackerStoredVisibilityRangeDB>,
    expected_events: Vec<TrackerEventVisibilityRangeDB>,
) -> Result<(), String> {
    let visibility = state.tracker_visibility.as_ref().ok_or_else(|| {
        "tracker subjects must expose tracker_visibility".to_owned()
    })?;

    if visibility.mode != expected_mode {
        return Err(format!(
            "unexpected tracker visibility mode: got {:?}, expected {:?}",
            visibility.mode, expected_mode
        ));
    }

    if visibility.stored_ranges != expected_stored {
        return Err(format!(
            "unexpected stored visibility ranges: got {:?}, expected {:?}",
            visibility.stored_ranges, expected_stored
        ));
    }

    if visibility.event_ranges != expected_events {
        return Err(format!(
            "unexpected event visibility ranges: got {:?}, expected {:?}",
            visibility.event_ranges, expected_events
        ));
    }

    Ok(())
}


// ----------------------------------------------------------------
// Contract fixtures and assertions shared by the governance and
// compiler e2e suites.
// ----------------------------------------------------------------

#[allow(dead_code)]
pub const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

#[allow(dead_code)]
pub const INVALID_EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXp";

#[allow(dead_code)]
pub const FUEL_EXHAUSTING_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIGxldCBtdXQgYnVybjogdTY0ID0gZGF0YSBhcyB1NjQ7CiAgICAgICAgbG9vcCB7CiAgICAgICAgICBidXJuID0gYnVybi53cmFwcGluZ19tdWwoMzEpLndyYXBwaW5nX2FkZCg3KTsKICAgICAgICAgIHN0YXRlLm9uZSA9IChidXJuICUgMTAwMCkgYXMgdTMyOwogICAgICAgIH0KICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVHdvIHsgZGF0YSB9ID0+IHsKICAgICAgICBzdGF0ZS50d28gPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RUaHJlZSB7IGRhdGEgfSA9PiB7CiAgICAgICAgaWYgZGF0YSA9PSA1MCB7CiAgICAgICAgICBjb250cmFjdF9yZXN1bHQuZXJyb3IgPSAiQ2FuIG5vdCBjaGFuZ2UgdGhyZWUgdmFsdWUsIDUwIGlzIGEgaW52YWxpZCB2YWx1ZSIudG9fb3duZWQoKTsKICAgICAgICAgIHJldHVybgogICAgICAgIH0KICAgICAgICAKICAgICAgICBzdGF0ZS50aHJlZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZEFsbCB7IG9uZSwgdHdvLCB0aHJlZSB9ID0+IHsKICAgICAgICBzdGF0ZS5vbmUgPSBvbmU7CiAgICAgICAgc3RhdGUudHdvID0gdHdvOwogICAgICAgIHN0YXRlLnRocmVlID0gdGhyZWU7CiAgICAgIH0KICB9CiAgY29udHJhY3RfcmVzdWx0LnN1Y2Nlc3MgPSB0cnVlOwp9";

#[allow(dead_code)]
pub const CHANGED_SCHEMA_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgZGF0YTogU3RyaW5nCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0KZW51bSBTdGF0ZUV2ZW50IHsKICBDaGFuZ2VEYXRhIHsgZGF0YTogU3RyaW5nIH0sCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gbWFpbl9mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMiwgaW5pdF9zdGF0ZV9wdHI6IGkzMiwgZXZlbnRfcHRyOiBpMzIsIGlzX293bmVyOiBpMzIpIC0+IHUzMiB7CiAgc2RrOjpleGVjdXRlX2NvbnRyYWN0KHN0YXRlX3B0ciwgaW5pdF9zdGF0ZV9wdHIsIGV2ZW50X3B0ciwgaXNfb3duZXIsIGNvbnRyYWN0X2xvZ2ljKQp9CgojW3Vuc2FmZShub19tYW5nbGUpXQpwdWIgdW5zYWZlIGZuIGluaXRfY2hlY2tfZnVuY3Rpb24oc3RhdGVfcHRyOiBpMzIpIC0+IHUzMiB7CiAgc2RrOjpjaGVja19pbml0X2RhdGEoc3RhdGVfcHRyLCBpbml0X2xvZ2ljKQp9CgpmbiBpbml0X2xvZ2ljKAogIF9zdGF0ZTogJlN0YXRlLAogIGNvbnRyYWN0X3Jlc3VsdDogJm11dCBzZGs6OkNvbnRyYWN0SW5pdENoZWNrLAopIHsKICBjb250cmFjdF9yZXN1bHQuc3VjY2VzcyA9IHRydWU7Cn0KCmZuIGNvbnRyYWN0X2xvZ2ljKAogIGNvbnRleHQ6ICZzZGs6OkNvbnRleHQ8U3RhdGVFdmVudD4sCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RSZXN1bHQ8U3RhdGU+LAopIHsKICBsZXQgc3RhdGUgPSAmbXV0IGNvbnRyYWN0X3Jlc3VsdC5zdGF0ZTsKICBtYXRjaCBjb250ZXh0LmV2ZW50LmNsb25lKCkgewogICAgICBTdGF0ZUV2ZW50OjpDaGFuZ2VEYXRhIHsgZGF0YSB9ID0+IHsKICAgICAgICBzdGF0ZS5kYXRhID0gZGF0YS5jbG9uZSgpOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQo=";

// Misma lógica que EXAMPLE_CONTRACT pero sin el rechazo de ModThree=50:
// sirve para discriminar qué versión del contrato evaluó un nodo.
#[allow(dead_code)]
pub const EXAMPLE_CONTRACT_V2: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLnRocmVlID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kQWxsIHsgb25lLCB0d28sIHRocmVlIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IG9uZTsKICAgICAgICBzdGF0ZS50d28gPSB0d287CiAgICAgICAgc3RhdGUudGhyZWUgPSB0aHJlZTsKICAgICAgfQogIH0KICBjb250cmFjdF9yZXN1bHQuc3VjY2VzcyA9IHRydWU7Cn0=";

#[track_caller]
#[allow(dead_code)]
pub fn assert_governance_properties_eq(actual: Value, expected: GovernanceData) {
    let actual: GovernanceData = from_value(actual).unwrap();
    assert_eq!(actual, expected);
}

#[track_caller]
#[allow(dead_code)]
pub fn governance_properties(actual: Value) -> GovernanceData {
    from_value(actual).unwrap()
}

#[allow(dead_code)]
pub async fn wait_sink_events(
    node: &ave_core::Api,
    subject_id: DigestIdentifier,
    expected_len: usize,
) -> Result<Vec<DataToSink>, Box<dyn Error>> {
    let mut attempts = 0;
    loop {
        let page = node
            .get_sink_events(
                subject_id.clone(),
                SinkEventsQuery {
                    from_sn: Some(0),
                    to_sn: None,
                    limit: Some(100),
                },
            )
            .await?;

        if page.events.len() == expected_len {
            return Ok(page.events);
        }

        if attempts > 100 {
            return Err(format!(
                "timeout waiting for sink events for subject {} at len {}, actual len {}",
                subject_id,
                expected_len,
                page.events.len()
            )
            .into());
        }

        attempts += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// Espera acotada a que el artefacto wasm de un schema exista en disco y
// devuelve sus bytes.
#[allow(dead_code)]
pub async fn wait_artifact_bytes(
    contracts_path: &std::path::Path,
    artifact_name: &str,
) -> Vec<u8> {
    // persist_artifact (compilation/pipeline.rs) escribe contract.wasm
    // PRIMERO y contract.cwasm después: un wasm legible puede ser un
    // prefijo en plena escritura. Exigir el cwasm garantiza que la
    // escritura del wasm ya terminó.
    let dir = contracts_path.join("contracts").join(artifact_name);
    let path = dir.join("contract.wasm");
    let precompiled = dir.join("contract.cwasm");
    for _ in 0..100 {
        if precompiled.exists()
            && let Ok(bytes) = fs::read(&path)
        {
            return bytes;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("timeout waiting for artifact {}", path.display());
}

// Espera acotada a que el artefacto wasm de un schema exista en disco
// con exactamente los bytes esperados (cubre el caso tampered: el
// fichero existe con basura hasta que el refetch lo reemplaza).
#[allow(dead_code)]
pub async fn wait_artifact_bytes_eq(
    contracts_path: &std::path::Path,
    artifact_name: &str,
    expected: &[u8],
) {
    // Misma carrera que wait_artifact_bytes: exigir el cwasm (escrito
    // después del wasm) antes de comparar.
    let dir = contracts_path.join("contracts").join(artifact_name);
    let path = dir.join("contract.wasm");
    let precompiled = dir.join("contract.cwasm");
    for _ in 0..100 {
        if precompiled.exists()
            && let Ok(bytes) = fs::read(&path)
            && bytes == expected
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!(
        "timeout waiting for artifact {} with expected bytes",
        path.display()
    );
}
