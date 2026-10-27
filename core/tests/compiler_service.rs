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
use ave_core::compilation::pipeline;
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

/// Local system-cargo build through the shared `ave-build`
/// procedure (same as the node): decode, resolve sysroot, build,
/// load. Mirrors the retired `pipeline::build_wasm` exactly.
async fn local_build_wasm(
    source: &str,
    build_dir: &std::path::Path,
    root: &std::path::Path,
) -> Vec<u8> {
    local_build_wasm_with_toolchain(source, build_dir, root, "", false).await
}

/// Direct in-process build through the shared procedure. `sandbox`
/// selects the production sandbox explicitly: suites default to
/// `false` so they never depend on namespace support, except the
/// dedicated sandbox tests.
async fn local_build_wasm_sandboxed(
    source: &str,
    build_dir: &std::path::Path,
    root: &std::path::Path,
) -> Vec<u8> {
    local_build_wasm_with_toolchain(source, build_dir, root, "", true).await
}

async fn local_build_wasm_with_toolchain(
    source: &str,
    build_dir: &std::path::Path,
    root: &std::path::Path,
    toolchain: &str,
    sandbox: bool,
) -> Vec<u8> {
    use ave_contract_sdk::runtime::CONTRACT_CARGO_CONFIG;
    let decoded =
        pipeline::decode_contract_source(source).expect("valid payload");
    let (rust_src, rustc_commit) =
        ave_build::query_sysroot(toolchain).await.expect("sysroot");
    let manifest_toml = pipeline::compilation_toml();
    let vendor_dir = {
        let vendor_root = root.join("vendor");
        if !vendor_root.exists() {
            None
        } else {
            ave_common::build::absolute_vendor_dir(build_dir, root)
        }
    };
    let request = ave_build::BuildRequest {
        source: &decoded,
        manifest_toml: &manifest_toml,
        config_template: CONTRACT_CARGO_CONFIG,
        lockfile: None,
        target_dir: std::path::PathBuf::from(".build-target"),
        vendor_dir,
        cargo_home: root.join(".cargo-home"),
        toolchain,
        cargo: if toolchain.is_empty() {
            ave_build::CargoProgram::System
        } else {
            ave_build::CargoProgram::Rustup(toolchain)
        },
        rust_src,
        rustc_commit,
        offline: root.join("vendor").exists(),
        locked: false,
        timeout: None,
        kill_process_group: false,
        sandbox,
    };
    ave_build::build_contract_wasm(build_dir, &request)
        .await
        .expect("local build should succeed")
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
    let (first, second) = tokio::join!(
        client.compile(&source, ""),
        client.compile(&source, ""),
    );
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
        .compile(&source, "")
        .await
        .expect("initial compile should succeed");

    let before = counter(server);
    let started_at = Instant::now();
    let outcome = client
        .compile(&source, "")
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

/// Same source under a named toolchain is its own cache entry,
/// attested with that toolchain's fingerprint: the first request
/// builds, the second is served without a new build.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn compile_named_toolchain_isolated_cache_entry() {
    let server = shared_server().await;
    let client = client_for(&server.endpoint);
    let source = source_b64(CONTRACT_C);

    let before = counter(server);
    let first = client
        .compile(&source, "1.95.0")
        .await
        .expect("named toolchain compile should succeed");
    assert_eq!(
        counter(server) - before,
        1,
        "first named-toolchain compile must build"
    );
    assert!(!first.wasm.is_empty());

    let expected = ave_build::toolchain_fingerprint(
        HashAlgorithm::Blake3,
        "1.95.0",
        ave_contract_sdk::runtime::CONTRACT_CARGO_CONFIG,
    )
    .await
    .expect("pinned toolchain fingerprint should compute");
    assert_eq!(first.toolchain_fingerprint, expected);

    let before = counter(server);
    let second = client
        .compile(&source, "1.95.0")
        .await
        .expect("cached named-toolchain compile should succeed");
    assert_eq!(
        counter(server),
        before,
        "a cached named-toolchain compile must not rebuild"
    );
    assert_eq!(second.wasm, first.wasm);
    assert_eq!(second.wasm_hash, first.wasm_hash);
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
            toolchain: String::new(),
        }))
        .await;
    let status = no_key.expect_err("request without API key must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    let mut request = Request::new(pb::CompileRequest {
        source_b64: source_b64(CONTRACT_B),
        toolchain: String::new(),
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
        .compile(&source_b64(CONTRACT_B), "")
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

    let result = client.compile(&source_b64(CONTRACT_B), "").await;
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
    let mut entries: Vec<String> =
        std::fs::read_dir(server._root.path().join("artifacts"))
            .expect("artifacts dir must exist")
            .filter_map(|entry| {
                let entry = entry.expect("entry must be readable");
                entry
                    .file_type()
                    .ok()?
                    .is_dir()
                    .then(|| entry.file_name().to_string_lossy().into_owned())
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
        .compile(&source, "")
        .await
        .expect("initial compile should succeed");

    // The entry created by the compile above belongs to CONTRACT_C.
    let entry_dir = artifact_entries(server)
        .into_iter()
        .find(|entry| !before_entries.contains(entry))
        .expect("the compile must create a new artifact store entry");
    let entry_path = server._root.path().join("artifacts").join(&entry_dir);

    // Corrupt the wasm bytes: the hash check must drop the entry and the
    // compile must rebuild it, serving the same good artifact.
    std::fs::write(entry_path.join("contract.wasm"), b"corrupted")
        .expect("wasm file must be writable");
    let before = counter(server);
    let rebuilt = client
        .compile(&source, "")
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
        .compile(&source, "")
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

/// Same minimal contract with a different field: a fixed source used by
/// the parity test below (kept apart from the other fixtures so their
/// cache/corruption assertions never see this entry).
const CONTRACT_D: &str = r#"
use serde::{Serialize, Deserialize};
use ave_contract_sdk as sdk;

#[derive(Serialize, Deserialize, Clone)]
struct State {
    pub four: u32,
}

#[derive(Serialize, Deserialize)]
enum StateEvent {
    ModFour { data: u32 },
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
    let StateEvent::ModFour { data } = context.event;
    contract_result.state.four = data;
}
"#;

/// Pool/local build parity: the same source compiled through the gRPC
/// server and through a direct in-process `pipeline::build_wasm` call
/// produces byte-identical wasm — both paths run the same pipeline with
/// the same manifest and toolchain, so the served artifact must match a
/// local build exactly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn compile_parity_with_local_build() {
    let server = shared_server().await;
    let client = client_for(&server.endpoint);
    let source = source_b64(CONTRACT_D);

    let remote = client
        .compile(&source, "")
        .await
        .expect("remote compile should succeed");

    // Same layout the service uses for its build jobs
    // (<root>/contracts/<key>): the pipeline derives the contracts root
    // (and the absent vendor directory) from it identically.
    let root = tempfile::tempdir().expect("failed to create build tempdir");
    let build_dir = root.path().join("contracts").join("parity");
    let local = local_build_wasm(&source, &build_dir, root.path()).await;

    assert_eq!(
        remote.wasm, local,
        "the pooled build and the local build must be byte-identical"
    );
}

/// Pinned-toolchain honesty: the pool builds with the requested
/// toolchain, not ambient. For each pinned toolchain the pooled bytes
/// must equal an independent local build with that toolchain (so a
/// pool mix-up can not feed every compiler the same wrong bytes
/// unanimously), and the two toolchains must diverge from each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn compile_pinned_toolchain_matches_local_build() {
    let server = shared_server().await;
    let client = client_for(&server.endpoint);
    let source = source_b64(CONTRACT_D);

    let mut pooled = Vec::new();
    for toolchain in ["1.95.0", "1.98.1"] {
        let remote = client
            .compile(&source, toolchain)
            .await
            .unwrap_or_else(|e| {
                panic!("remote {toolchain} compile should succeed: {e}")
            });

        let root =
            tempfile::tempdir().expect("failed to create build tempdir");
        let build_dir =
            root.path().join("contracts").join(format!("parity-{toolchain}"));
        let local = local_build_wasm_with_toolchain(
            &source,
            &build_dir,
            root.path(),
            toolchain,
            false,
        )
        .await;

        assert_eq!(
            remote.wasm, local,
            "pooled {toolchain} bytes must equal a local {toolchain} build"
        );
        pooled.push(remote.wasm);
    }
    assert_ne!(
        pooled[0], pooled[1],
        "the two pinned toolchains must produce different bytes"
    );
}

/// Root independence: the same source built through
/// `pipeline::build_wasm` under two different contracts roots (the
/// contracts path is configurable per node) produces byte-identical
/// wasm, and no machine-absolute path leaks into the artifact — neither
/// the roots themselves nor the toolchain sysroot (rust-src component);
/// only canonical `/cargo-home/...` and `/rustc/<commit>/...` paths may
/// be embedded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn local_build_is_byte_identical_across_contract_roots() {
    let source = source_b64(CONTRACT_D);

    let root_a = tempfile::tempdir().expect("failed to create tempdir A");
    let root_b = tempfile::tempdir().expect("failed to create tempdir B");
    let build_a = root_a.path().join("contracts").join("parity");
    let build_b = root_b.path().join("contracts").join("parity");

    let wasm_a =
        local_build_wasm_sandboxed(&source, &build_a, root_a.path()).await;
    let wasm_b =
        local_build_wasm_sandboxed(&source, &build_b, root_b.path()).await;

    assert_eq!(
        wasm_a, wasm_b,
        "the contracts root must not shape the artifact bytes"
    );

    let sysroot = std::process::Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .expect("rustc --print sysroot should run");
    let mut forbidden: Vec<Vec<u8>> = [root_a.path(), root_b.path()]
        .into_iter()
        .map(|p| p.to_string_lossy().as_bytes().to_vec())
        .collect();
    forbidden.push(
        String::from_utf8_lossy(&sysroot.stdout)
            .trim()
            .as_bytes()
            .to_vec(),
    );
    for needle in forbidden {
        assert!(
            !wasm_a.windows(needle.len()).any(|w| w == needle),
            "the artifact embeds {}",
            String::from_utf8_lossy(&needle)
        );
    }
}

/// Copies a directory tree (plants identical vendor sources under
/// two different roots).
fn copy_dir_tree(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).expect("create vendor copy");
    let entries = std::fs::read_dir(src).expect("read vendor sources");
    for entry in entries {
        let entry = entry.expect("vendor entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy vendor file");
        }
    }
}

/// Real vendored dep set for the frozen lockfile, generated once per
/// test process with the system cargo. Content-identical for every
/// consumer; only the planting path differs.
async fn shared_vendor_dir() -> std::path::PathBuf {
    static VENDOR: OnceCell<TempDir> = OnceCell::const_new();
    let root = VENDOR
        .get_or_init(|| async {
            tempfile::tempdir().expect("failed to create vendor tempdir")
        })
        .await;
    let probe = root.path().join("vendor");
    if !probe.exists() {
        let project = root.path().join("project");
        std::fs::create_dir_all(project.join("src"))
            .expect("create vendor project");
        std::fs::write(project.join("src").join("lib.rs"), "")
            .expect("write vendor stub source");
        std::fs::write(project.join("Cargo.toml"), pipeline::compilation_toml())
            .expect("write vendor manifest");
        let frozen = ave_common::build::pin_lockfile(
            ave_common::governance::DEFAULT_PIN,
        )
        .expect("frozen lockfile for the active pin");
        std::fs::write(project.join("Cargo.lock"), frozen.content)
            .expect("write vendor lockfile");
        let status = std::process::Command::new("cargo")
            .arg("vendor")
            .arg("--manifest-path")
            .arg(project.join("Cargo.toml"))
            .arg(&probe)
            .status()
            .expect("cargo vendor should run");
        assert!(status.success(), "cargo vendor should succeed");
    }
    probe
}

/// Production offline build through the shared procedure: frozen
/// lockfile, vendored sources, pinned toolchain. No sandbox: suites
/// never depend on namespace support, and the remap under test is
/// config-level so it applies either way.
async fn local_build_wasm_vendored(
    source: &str,
    build_dir: &std::path::Path,
    root: &std::path::Path,
) -> Vec<u8> {
    use ave_contract_sdk::runtime::CONTRACT_CARGO_CONFIG;
    let decoded =
        pipeline::decode_contract_source(source).expect("valid payload");
    let (rust_src, rustc_commit) =
        ave_build::query_sysroot("1.95.0").await.expect("sysroot");
    let manifest_toml = pipeline::compilation_toml();
    let frozen = ave_common::build::pin_lockfile(
        ave_common::governance::DEFAULT_PIN,
    )
    .expect("frozen lockfile for the active pin");
    let vendor_dir = ave_common::build::absolute_vendor_dir(build_dir, root);
    assert!(vendor_dir.is_some(), "vendor dir must resolve");
    let request = ave_build::BuildRequest {
        source: &decoded,
        manifest_toml: &manifest_toml,
        config_template: CONTRACT_CARGO_CONFIG,
        lockfile: Some(frozen.content),
        target_dir: std::path::PathBuf::from(".build-target"),
        vendor_dir,
        cargo_home: root.join(".cargo-home"),
        toolchain: "1.95.0",
        cargo: ave_build::CargoProgram::Rustup("1.95.0"),
        rust_src,
        rustc_commit,
        offline: true,
        locked: true,
        timeout: None,
        kill_process_group: false,
        sandbox: false,
    };
    ave_build::build_contract_wasm(build_dir, &request)
        .await
        .expect("vendored build should succeed")
}

/// Vendored root independence (regression: production offline builds
/// embedded the absolute vendor path, including the random staging
/// suffix, so the same source built twice gave different bytes and
/// multi-compiler quorums could never agree). The same source under
/// two roots with real vendored deps must give byte-identical wasm,
/// with dep paths remapped to canonical `/vendor/...` and no
/// machine-absolute path inside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn vendored_build_is_byte_identical_across_contract_roots() {
    let source = source_b64(CONTRACT_D);
    let vendor_src = shared_vendor_dir().await;

    let root_a = tempfile::tempdir().expect("failed to create tempdir A");
    let root_b = tempfile::tempdir().expect("failed to create tempdir B");
    copy_dir_tree(&vendor_src, &root_a.path().join("vendor"));
    copy_dir_tree(&vendor_src, &root_b.path().join("vendor"));
    let build_a = root_a.path().join("contracts").join("parity");
    let build_b = root_b.path().join("contracts").join("parity");

    let wasm_a =
        local_build_wasm_vendored(&source, &build_a, root_a.path()).await;
    let wasm_b =
        local_build_wasm_vendored(&source, &build_b, root_b.path()).await;

    assert_eq!(
        wasm_a, wasm_b,
        "the vendor dir must not shape the artifact bytes"
    );

    // Canonical remap evidence: vendored dep paths live under /vendor/.
    assert!(
        wasm_a.windows(8).any(|w| w == b"/vendor/"),
        "vendored dep paths must be remapped to /vendor/"
    );
    let sysroot = std::process::Command::new("rustup")
        .args(["run", "1.95.0", "rustc", "--print", "sysroot"])
        .output()
        .expect("rustc --print sysroot should run");
    let mut forbidden: Vec<Vec<u8>> = vec![
        root_a.path().to_path_buf(),
        root_b.path().to_path_buf(),
        root_a.path().join("vendor"),
        root_b.path().join("vendor"),
    ]
    .into_iter()
    .map(|p| p.to_string_lossy().as_bytes().to_vec())
    .collect();
    forbidden.push(
        String::from_utf8_lossy(&sysroot.stdout)
            .trim()
            .as_bytes()
            .to_vec(),
    );
    for needle in forbidden {
        assert!(
            !wasm_a.windows(needle.len()).any(|w| w == needle),
            "the artifact embeds {}",
            String::from_utf8_lossy(&needle)
        );
    }
}

/// Malicious shape (mirrors `example-malicious` in ave-contract-sdk):
/// reads host env at compile time. The node build environment is
/// scrubbed, so this must fail to compile even when the outer
/// process exports the variable.
const CONTRACT_ENV_SENTINEL: &str = r#"
use serde::{Serialize, Deserialize};
use ave_contract_sdk as sdk;

const STOLEN: &str = env!("AVE_SECRET_SENTINEL");

#[derive(Serialize, Deserialize, Clone)]
struct State {
    pub four: u32,
}

#[derive(Serialize, Deserialize)]
enum StateEvent {
    ModFour { data: u32 },
}

#[unsafe(no_mangle)]
pub unsafe fn main_function(
    state_ptr: i32,
    init_state_ptr: i32,
    event_ptr: i32,
    is_owner: i32,
) -> u32 {
    let _ = STOLEN.len();
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
    let StateEvent::ModFour { data } = context.event;
    contract_result.state.four = data;
}
"#;

/// Fallible local build through the shared `ave-build` procedure:
/// same steps as `local_build_wasm` but returns the error instead
/// of panicking, so negative tests can assert rejection.
async fn try_local_build_wasm(
    source_b64: &str,
    build_dir: &std::path::Path,
    root: &std::path::Path,
    sandbox: bool,
) -> Result<Vec<u8>, String> {
    use ave_contract_sdk::runtime::CONTRACT_CARGO_CONFIG;
    let decoded = pipeline::decode_contract_source(source_b64)
        .map_err(|e| e.to_string())?;
    let (rust_src, rustc_commit) =
        ave_build::query_sysroot("").await.map_err(|e| e.to_string())?;
    let manifest_toml = pipeline::compilation_toml();
    let request = ave_build::BuildRequest {
        source: &decoded,
        manifest_toml: &manifest_toml,
        config_template: CONTRACT_CARGO_CONFIG,
        lockfile: None,
        target_dir: std::path::PathBuf::from(".build-target"),
        vendor_dir: None,
        cargo_home: root.join(".cargo-home"),
        toolchain: "",
        cargo: ave_build::CargoProgram::System,
        rust_src,
        rustc_commit,
        offline: false,
        locked: false,
        timeout: None,
        kill_process_group: false,
        sandbox,
    };
    ave_build::build_contract_wasm(build_dir, &request)
        .await
        .map_err(|e| e.to_string())
}

/// Outer environment must not shape artifacts: the same source
/// built with different `AVE_SECRET_SENTINEL` values produces
/// byte-identical wasm without the secret embedded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn local_build_ignores_outer_env_sentinel() {
    let source = source_b64(CONTRACT_D);
    // Distinct outer values; the build environment is scrubbed, so
    // both builds must behave as if the variable were absent.
    // `set_var` is unsafe in Rust 2024; this suite is `#[serial]`.
    unsafe { std::env::set_var("AVE_SECRET_SENTINEL", "outer-value-a") };
    let root_a = tempfile::tempdir().expect("failed to create tempdir A");
    let build_a = root_a.path().join("contracts").join("env-a");
    let wasm_a =
        local_build_wasm_sandboxed(&source, &build_a, root_a.path()).await;

    unsafe { std::env::set_var("AVE_SECRET_SENTINEL", "outer-value-b") };
    let root_b = tempfile::tempdir().expect("failed to create tempdir B");
    let build_b = root_b.path().join("contracts").join("env-b");
    let wasm_b =
        local_build_wasm_sandboxed(&source, &build_b, root_b.path()).await;
    unsafe { std::env::remove_var("AVE_SECRET_SENTINEL") };

    assert_eq!(
        wasm_a, wasm_b,
        "outer env must not shape the artifact bytes"
    );
    for sentinel in [b"outer-value-a".as_slice(), b"outer-value-b".as_slice()] {
        assert!(
            !wasm_a
                .windows(sentinel.len())
                .any(|w| w == sentinel),
            "the artifact embeds outer env"
        );
    }
}

/// A contract reading host env at compile time is rejected: the
/// scrubbed build environment hides `AVE_SECRET_SENTINEL`, so
/// `env!` fails the build instead of embedding the secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn local_build_rejects_env_sentinel_contract() {
    unsafe { std::env::set_var("AVE_SECRET_SENTINEL", "top-secret-value") };
    let source = source_b64(CONTRACT_ENV_SENTINEL);
    let root = tempfile::tempdir().expect("failed to create tempdir");
    let build_dir = root.path().join("contracts").join("env-evil");
    let result =
        try_local_build_wasm(&source, &build_dir, root.path(), true).await;
    unsafe { std::env::remove_var("AVE_SECRET_SENTINEL") };

    assert_eq!(
        result,
        Err("cargo build failed".to_owned()),
        "a contract using env! on host secrets must fail compilation, \
         not sandbox staging"
    );
}

/// Shape shared by the file-exfiltration probes below: identical to
/// `CONTRACT_D` but embedding an absolute host path at compile time.
/// The sandbox root contains no such path, so the build must fail
/// instead of smuggling host bytes into the artifact.
fn contract_with_included_file(abs_path: &str) -> String {
    format!(
        r#"
use serde::{{Serialize, Deserialize}};
use ave_contract_sdk as sdk;

const LEAK: &[u8] = include_bytes!("{abs_path}");

#[derive(Serialize, Deserialize, Clone)]
struct State {{
    pub four: u32,
}}

#[derive(Serialize, Deserialize)]
enum StateEvent {{
    ModFour {{ data: u32 }},
}}

#[unsafe(no_mangle)]
pub unsafe fn main_function(
    state_ptr: i32,
    init_state_ptr: i32,
    event_ptr: i32,
    is_owner: i32,
) -> u32 {{
    let _ = LEAK.len();
    sdk::execute_contract(
        state_ptr,
        init_state_ptr,
        event_ptr,
        is_owner,
        contract_logic,
    )
}}

#[unsafe(no_mangle)]
pub unsafe fn init_check_function(state_ptr: i32) -> u32 {{
    sdk::check_init_data(state_ptr, init_logic)
}}

fn init_logic(
    _state: &State,
    contract_result: &mut sdk::ContractInitCheck,
) {{
    contract_result.success = true;
}}

fn contract_logic(
    context: &sdk::Context<StateEvent>,
    contract_result: &mut sdk::ContractResult<State>,
) {{
    let StateEvent::ModFour {{ data }} = context.event;
    contract_result.state.four = data;
}}
"#
    )
}

/// A secret placed in the real home directory is unreachable inside
/// the sandbox: only the toolchain, loader libraries, vendor,
/// cargo home and build directory exist there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn local_build_cannot_read_home_secret() {
    let home = std::env::var_os("HOME").expect("HOME must be set");
    let secret_path =
        std::path::Path::new(&home).join(".ave-sandbox-test-secret");
    std::fs::write(&secret_path, b"sandbox-secret-value")
        .expect("secret fixture must be writable");
    let source = BASE64_STANDARD.encode(contract_with_included_file(
        &secret_path.to_string_lossy(),
    ));
    let root = tempfile::tempdir().expect("failed to create tempdir");
    let build_dir = root.path().join("contracts").join("home-evil");
    let result =
        try_local_build_wasm(&source, &build_dir, root.path(), true).await;
    std::fs::remove_file(&secret_path).ok();

    let err = result.expect_err(
        "a contract including a host file must not compile in the sandbox",
    );
    assert_eq!(
        err, "cargo build failed",
        "a contract including a host file must fail compilation, \
         not sandbox staging: {err}"
    );
    assert!(
        !err.contains("sandbox-secret-value"),
        "the error itself leaks the secret: {err}"
    );
}

/// Host identity files are absent from the sandbox root as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn local_build_cannot_read_etc_hostname() {
    let source = BASE64_STANDARD
        .encode(contract_with_included_file("/etc/hostname"));
    let root = tempfile::tempdir().expect("failed to create tempdir");
    let build_dir = root.path().join("contracts").join("etc-evil");
    let result =
        try_local_build_wasm(&source, &build_dir, root.path(), true).await;

    assert_eq!(
        result,
        Err("cargo build failed".to_owned()),
        "a contract including /etc/hostname must fail compilation, \
         not sandbox staging"
    );
}
