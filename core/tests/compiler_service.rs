//! End-to-end tests of the compiler service: a real in-process gRPC
//! server (ephemeral port, real cargo builds) exercised through the real
//! client. Builds are slow, so a single shared server is used and the
//! suite is serialized (`#[serial]`) to keep assertions deterministic.
#![cfg(feature = "test")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ave_common::compiler::pb;
use ave_common::compiler::pb::compiler_service_client::CompilerServiceClient;
use ave_common::identity::{DigestIdentifier, HashAlgorithm};
use ave_core::compilation::client::CompilerClient;
use ave_core::compilation::error::CompilerError;
use ave_core::compilation::service::CompilerServer;
use ave_core::compilation::service_config::ServiceConfig;
use base64::Engine as Base64Engine;
use base64::prelude::BASE64_STANDARD;
use serial_test::serial;
use tempfile::TempDir;
use tokio::sync::OnceCell;
use tonic::Request;
use tonic::metadata::MetadataValue;

/// Generous client timeout: the first build of a fresh work directory is
/// a cold cargo build, and the server-side build timeout is 600 s.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(700);

/// Minimal real contract (shape of `ave-contract-sdk/example`).
const CONTRACT_A: &str = r#"
use serde::{Serialize, Deserialize};
use ave_contract_sdk as sdk;

#[derive(Serialize, Deserialize, Clone)]
struct State {
    pub one: u32,
}

#[derive(Serialize, Deserialize)]
enum StateEvent {
    ModOne { data: u32 },
}

#[unsafe(no_mangle)]
pub unsafe fn main_function(
    state_ptr: i32,
    init_state_ptr: i32,
    event_ptr: i32,
    is_owner: i32,
) -> u32 {
    sdk::execute_contract(
        state_ptr,
        init_state_ptr,
        event_ptr,
        is_owner,
        contract_logic,
    )
}

#[unsafe(no_mangle)]
pub unsafe fn init_check_function(state_ptr: i32) -> u32 {
    sdk::check_init_data(state_ptr, init_logic)
}

fn init_logic(
    _state: &State,
    contract_result: &mut sdk::ContractInitCheck,
) {
    contract_result.success = true;
}

fn contract_logic(
    context: &sdk::Context<StateEvent>,
    contract_result: &mut sdk::ContractResult<State>,
) {
    let StateEvent::ModOne { data } = context.event;
    contract_result.state.one = data;
}
"#;

/// Same contract with a different field: a distinct source hash.
const CONTRACT_B: &str = r#"
use serde::{Serialize, Deserialize};
use ave_contract_sdk as sdk;

#[derive(Serialize, Deserialize, Clone)]
struct State {
    pub two: u32,
}

#[derive(Serialize, Deserialize)]
enum StateEvent {
    ModTwo { data: u32 },
}

#[unsafe(no_mangle)]
pub unsafe fn main_function(
    state_ptr: i32,
    init_state_ptr: i32,
    event_ptr: i32,
    is_owner: i32,
) -> u32 {
    sdk::execute_contract(
        state_ptr,
        init_state_ptr,
        event_ptr,
        is_owner,
        contract_logic,
    )
}

#[unsafe(no_mangle)]
pub unsafe fn init_check_function(state_ptr: i32) -> u32 {
    sdk::check_init_data(state_ptr, init_logic)
}

fn init_logic(
    _state: &State,
    contract_result: &mut sdk::ContractInitCheck,
) {
    contract_result.success = true;
}

fn contract_logic(
    context: &sdk::Context<StateEvent>,
    contract_result: &mut sdk::ContractResult<State>,
) {
    let StateEvent::ModTwo { data } = context.event;
    contract_result.state.two = data;
}
"#;

const API_KEY: &str = "test-compiler-api-key";

/// Server shared by the whole suite: one real gRPC server over a temp
/// work/artifacts area, so the full suite pays two builds in total.
struct SharedServer {
    endpoint: String,
    build_counter: Arc<AtomicU64>,
    _root: TempDir,
}

static SHARED: OnceCell<SharedServer> = OnceCell::const_new();

async fn shared_server() -> &'static SharedServer {
    SHARED
        .get_or_init(|| async {
            let root = tempfile::tempdir()
                .expect("failed to create compiler test tempdir");
            let config = ServiceConfig {
                api_keys: vec![API_KEY.to_owned()],
                max_concurrent_builds: Some(2),
                artifacts_dir: root.path().join("artifacts"),
                work_dir: root.path().join("work"),
                key_path: root.path().join("identity.der"),
                ..ServiceConfig::default()
            };
            let server = CompilerServer::new(config)
                .await
                .expect("compiler server should start");
            let build_counter = server.build_counter();

            let listener = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("failed to bind ephemeral port");
            let addr =
                listener.local_addr().expect("listener has a local address");

            // The server must outlive any single test runtime: each
            // `#[tokio::test]` drops its runtime on completion, which
            // would kill a task spawned here. Serve on a dedicated
            // thread with its own runtime instead; it lives until the
            // test process exits.
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("server runtime should build");
                runtime.block_on(async move {
                    let _ =
                        server.serve(listener, std::future::pending()).await;
                });
            });

            SharedServer {
                endpoint: format!("http://{addr}"),
                build_counter,
                _root: root,
            }
        })
        .await
}

fn source_b64(source: &str) -> String {
    BASE64_STANDARD.encode(source)
}

fn client_for(endpoint: &str) -> CompilerClient {
    CompilerClient::new(
        vec![endpoint.to_owned()],
        API_KEY.to_owned(),
        None,
        None,
        Some(CLIENT_TIMEOUT),
        None,
    )
}

fn counter(server: &SharedServer) -> u64 {
    server.build_counter.load(Ordering::SeqCst)
}

/// Two concurrent compiles of the same source must produce a single
/// build; both callers receive the same attested artifact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn compile_dedup_single_flight() {
    let server = shared_server().await;
    let client = client_for(&server.endpoint);
    let source = source_b64(CONTRACT_A);

    let before = counter(server);
    let (first, second) =
        tokio::join!(client.compile(&source), client.compile(&source),);
    let first = first.expect("first concurrent compile should succeed");
    let second = second.expect("second concurrent compile should succeed");

    assert_eq!(
        counter(server) - before,
        1,
        "two concurrent compiles of the same source must run one build"
    );
    assert_eq!(first.wasm, second.wasm);
    assert_eq!(first.wasm_hash, second.wasm_hash);
    assert_eq!(first.source_hash, second.source_hash);
    assert!(!first.wasm.is_empty());
}

/// A repeated compile of a cached source is a cache hit: fast and with
/// no new build.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn compile_cache_hit() {
    let server = shared_server().await;
    let client = client_for(&server.endpoint);
    let source = source_b64(CONTRACT_B);

    // Ensure the artifact exists (builds only on the first call).
    client
        .compile(&source)
        .await
        .expect("initial compile should succeed");

    let before = counter(server);
    let started_at = Instant::now();
    let outcome = client
        .compile(&source)
        .await
        .expect("cached compile should succeed");
    let elapsed = started_at.elapsed();

    assert_eq!(
        counter(server),
        before,
        "a cached compile must not trigger a new build"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "cache hit took too long: {elapsed:?}"
    );
    assert!(!outcome.wasm.is_empty());
}

/// Requests without an API key or with an unknown one are rejected with
/// UNAUTHENTICATED before any build happens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn compile_auth_rejected() {
    let server = shared_server().await;
    let before = counter(server);

    let mut client = CompilerServiceClient::connect(server.endpoint.clone())
        .await
        .expect("failed to connect to the compiler service");

    let no_key = client
        .compile(Request::new(pb::CompileRequest {
            source_b64: source_b64(CONTRACT_B),
        }))
        .await;
    let status = no_key.expect_err("request without API key must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    let mut request = Request::new(pb::CompileRequest {
        source_b64: source_b64(CONTRACT_B),
    });
    request
        .metadata_mut()
        .insert("x-api-key", MetadataValue::from_static("wrong-key"));
    let wrong_key = client.compile(request).await;
    let status = wrong_key.expect_err("request with wrong API key must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    assert_eq!(
        counter(server),
        before,
        "rejected requests must not trigger builds"
    );
}

/// The client fails over in order: a dead first endpoint is skipped and
/// the second one serves the compile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn client_failover() {
    let server = shared_server().await;

    // A port that is guaranteed to be closed.
    let dead = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve a dead port");
    let dead_addr = dead.local_addr().expect("listener has an address");
    drop(dead);

    let client = CompilerClient::new(
        vec![format!("http://{dead_addr}"), server.endpoint.clone()],
        API_KEY.to_owned(),
        None,
        None,
        Some(CLIENT_TIMEOUT),
        None,
    );

    let outcome = client
        .compile(&source_b64(CONTRACT_B))
        .await
        .expect("compile should succeed through the second endpoint");
    assert!(!outcome.wasm.is_empty());
}

/// A client pinning a different toolchain fingerprint rejects every
/// endpoint with ToolchainMismatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn client_toolchain_mismatch() {
    let server = shared_server().await;

    let bogus = DigestIdentifier::new(HashAlgorithm::Blake3, vec![0xAB; 32])
        .expect("bogus digest should be valid");
    let client = CompilerClient::new(
        vec![server.endpoint.clone()],
        API_KEY.to_owned(),
        Some(bogus),
        None,
        Some(CLIENT_TIMEOUT),
        None,
    );

    let result = client.compile(&source_b64(CONTRACT_B)).await;
    let error = result.expect_err("a toolchain mismatch must be an error");
    assert!(
        matches!(error, CompilerError::ToolchainMismatch { .. }),
        "expected ToolchainMismatch, got: {error}"
    );
}

/// Same minimal contract with a different field: a fresh source, so its
/// artifact store entry belongs to this test alone.
const CONTRACT_C: &str = r#"
use serde::{Serialize, Deserialize};
use ave_contract_sdk as sdk;

#[derive(Serialize, Deserialize, Clone)]
struct State {
    pub three: u32,
}

#[derive(Serialize, Deserialize)]
enum StateEvent {
    ModThree { data: u32 },
}

#[unsafe(no_mangle)]
pub unsafe fn main_function(
    state_ptr: i32,
    init_state_ptr: i32,
    event_ptr: i32,
    is_owner: i32,
) -> u32 {
    sdk::execute_contract(
        state_ptr,
        init_state_ptr,
        event_ptr,
        is_owner,
        contract_logic,
    )
}

#[unsafe(no_mangle)]
pub unsafe fn init_check_function(state_ptr: i32) -> u32 {
    sdk::check_init_data(state_ptr, init_logic)
}

fn init_logic(
    _state: &State,
    contract_result: &mut sdk::ContractInitCheck,
) {
    contract_result.success = true;
}

fn contract_logic(
    context: &sdk::Context<StateEvent>,
    contract_result: &mut sdk::ContractResult<State>,
) {
    let StateEvent::ModThree { data } = context.event;
    contract_result.state.three = data;
}
"#;

/// Names of the entries currently in the shared server's artifact store.
fn artifact_entries(server: &SharedServer) -> Vec<String> {
    let mut entries: Vec<String> = std::fs::read_dir(
        server._root.path().join("artifacts"),
    )
    .expect("artifacts dir must exist")
    .filter_map(|entry| {
        let entry = entry.expect("entry must be readable");
        entry.file_type().ok()?.is_dir().then(|| {
            entry.file_name().to_string_lossy().into_owned()
        })
    })
    .collect();
    entries.sort();
    entries
}

/// Artifact store integrity: an entry whose wasm bytes do not match the
/// persisted hash, and an entry missing the hash file, are dropped and
/// rebuilt — never served. Guards the `ArtifactStore::lookup` corruption
/// paths the rest of the suite does not exercise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn compile_artifact_store_corruption_rebuilds() {
    let server = shared_server().await;
    let client = client_for(&server.endpoint);
    let source = source_b64(CONTRACT_C);

    let before_entries = artifact_entries(server);
    let baseline = client
        .compile(&source)
        .await
        .expect("initial compile should succeed");

    // The entry created by the compile above belongs to CONTRACT_C.
    let entry_dir = artifact_entries(server)
        .into_iter()
        .find(|entry| !before_entries.contains(entry))
        .expect("the compile must create a new artifact store entry");
    let entry_path = server
        ._root
        .path()
        .join("artifacts")
        .join(&entry_dir);

    // Corrupt the wasm bytes: the hash check must drop the entry and the
    // compile must rebuild it, serving the same good artifact.
    std::fs::write(entry_path.join("contract.wasm"), b"corrupted")
        .expect("wasm file must be writable");
    let before = counter(server);
    let rebuilt = client
        .compile(&source)
        .await
        .expect("compile after wasm corruption should succeed");
    assert_eq!(
        counter(server) - before,
        1,
        "a corrupt entry must be rebuilt, not served"
    );
    assert_eq!(rebuilt.wasm, baseline.wasm);
    assert_eq!(rebuilt.wasm_hash, baseline.wasm_hash);

    // Remove the hash file: the entry is incomplete, so it must also be
    // dropped and rebuilt.
    std::fs::remove_file(entry_path.join("wasm.hash"))
        .expect("hash file must exist after the rebuild");
    let before = counter(server);
    let rebuilt = client
        .compile(&source)
        .await
        .expect("compile after hash file removal should succeed");
    assert_eq!(
        counter(server) - before,
        1,
        "an entry without hash file must be rebuilt, not served"
    );
    assert_eq!(rebuilt.wasm, baseline.wasm);
    assert_eq!(rebuilt.wasm_hash, baseline.wasm_hash);
}
