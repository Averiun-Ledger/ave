//! Embedded compiler service shared by every test binary (lib tests and
//! integration tests built with the `test` feature).
//!
//! The node never compiles contracts locally, so tests need a real
//! compiler: a single in-process gRPC server per test process, with its
//! own runtime thread (so it outlives the individual `#[tokio::test]`
//! runtimes). [`crate::system::system`] wires it automatically whenever
//! the node config has no compiler endpoints in a test build, so any
//! crate driving core with the `test` feature gets it with no extra
//! setup; an explicitly configured pool always wins. Its artifact store
//! lives in a fixed shared temp path, so the first process to build a
//! contract serves every other process and test run — same role as the
//! old shared artifact cache. Entries are content-addressed (source,
//! manifest, toolchain) and integrity-checked on read, so concurrent
//! writes from parallel test binaries can only cause a safe rebuild,
//! never a bad artifact.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ave_common::compiler::pb;
use ave_common::compiler::pb::compiler_service_server::{
    CompilerService, CompilerServiceServer,
};
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, KeyPair, KeyPairAlgorithm, hash_borsh,
};
use tokio::sync::{Mutex, Notify, OnceCell};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

use crate::compilation::client::CompilerClient;
use crate::compilation::pipeline;
use crate::compilation::service::MAX_MESSAGE_BYTES;
use crate::config::CompilerNodeConfig;

/// API key shared by the embedded compiler and the test nodes.
pub const TEST_COMPILER_API_KEY: &str = "test-compiler-api-key";

static COMPILER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Compiler service shared by every test of the process.
struct EmbeddedCompiler {
    endpoint: String,
    /// Keeps the root directory path referenced (left on disk, same
    /// policy as the test contract directories).
    _root: PathBuf,
}

static EMBEDDED_COMPILER: OnceCell<EmbeddedCompiler> = OnceCell::const_new();

/// Endpoint of the embedded compiler, starting it on first use.
async fn embedded_compiler_endpoint() -> String {
    EMBEDDED_COMPILER
        .get_or_init(|| async {
            let root = std::env::temp_dir().join(format!(
                "ave-test-compiler-{}-{}",
                std::process::id(),
                COMPILER_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&root)
                .expect("Can not create compiler directory");
            let config = crate::compilation::service_config::ServiceConfig {
                api_keys: vec![TEST_COMPILER_API_KEY.to_owned()],
                max_concurrent_builds: Some(2),
                // Shared across test processes: content-addressed entries,
                // first build wins, everyone else reuses.
                artifacts_dir: std::env::temp_dir()
                    .join("ave-test-compiler-artifacts"),
                work_dir: root.join("work"),
                key_path: root.join("identity.der"),
                ..crate::compilation::service_config::ServiceConfig::default()
            };
            let server = crate::compilation::service::CompilerServer::new(config)
                .await
                .expect("embedded compiler should start");
            let listener = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("Can not bind compiler port");
            let addr =
                listener.local_addr().expect("listener has a local address");
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("compiler runtime should build");
                runtime.block_on(async move {
                    let _ =
                        server.serve(listener, std::future::pending()).await;
                });
            });
            EmbeddedCompiler {
                endpoint: format!("http://{addr}"),
                _root: root,
            }
        })
        .await
        .endpoint
        .clone()
}

/// Node compiler configuration pointing at the embedded compiler, ready
/// to drop into a test [`crate::config::Config`].
pub async fn test_compiler_config() -> CompilerNodeConfig {
    CompilerNodeConfig {
        endpoints: vec![embedded_compiler_endpoint().await],
        api_key: Some(TEST_COMPILER_API_KEY.to_owned()),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Scripted compiler: a per-test gRPC compiler whose behavior the test
// controls, for scenarios the real pool cannot produce deterministically
// (slow builds, divergent outputs). The embedded compiler is untouched:
// the scripted server proxies it once per source to obtain a real
// artifact, applies its transform and caches the result.
// ---------------------------------------------------------------------------

static SCRIPTED_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Transform applied to the real artifact before the scripted compiler
/// serves it.
#[derive(Clone, Debug)]
pub enum ScriptedTransform {
    /// Serve the real artifact unchanged (slow-build scripting only).
    Identity,
    /// Append a wasm custom section named after the tag: the module
    /// stays valid and behaves identically (engines ignore custom
    /// sections), but its bytes and hash diverge per tag — a
    /// deterministic simulation of a non-reproducible compiler.
    CustomSection(String),
}

/// Shared control surface of a scripted compiler.
#[derive(Default)]
struct ScriptedControl {
    /// Compile requests received so far.
    compiles_received: AtomicU64,
    /// While set, compile responses block until `release`.
    held: AtomicBool,
    /// Wakes held compile handlers on release.
    release: Notify,
}

/// A scripted compiler service running on its own thread/runtime, with
/// an ephemeral endpoint. Drop nothing: it lives until the test process
/// exits, like the embedded compiler.
pub struct ScriptedCompiler {
    endpoint: String,
    public_key: String,
    control: Arc<ScriptedControl>,
}

impl ScriptedCompiler {
    /// Starts a scripted compiler applying `transform` to every artifact.
    pub fn start(transform: ScriptedTransform) -> Self {
        let key_pair = KeyPair::generate(KeyPairAlgorithm::Ed25519)
            .expect("scripted compiler identity should generate");
        let public_key = key_pair.public_key().to_string();
        // Unique fingerprint per instance: the global test cache is keyed
        // by toolchain, so a shared fingerprint would let one scripted
        // server serve another instance's transformed bytes.
        let id = SCRIPTED_COUNTER.fetch_add(1, Ordering::SeqCst);
        let toolchain_fingerprint = hash_borsh(
            &*HashAlgorithm::Blake3.hasher(),
            &format!("ave-scripted-compiler-{id}"),
        )
        .expect("scripted toolchain fingerprint should hash");
        let control = Arc::new(ScriptedControl::default());
        let service = ScriptedCompilerService {
            transform,
            key_pair,
            toolchain_fingerprint,
            control: Arc::clone(&control),
            cache: Mutex::new(HashMap::new()),
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("Can not bind scripted compiler port");
        let addr = listener.local_addr().expect("listener has a local address");

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("scripted compiler runtime should build");
            runtime.block_on(async move {
                listener
                    .set_nonblocking(true)
                    .expect("listener should accept non-blocking");
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("listener should convert");
                let service = CompilerServiceServer::new(service)
                    .max_decoding_message_size(MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES);
                let _ = tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming_shutdown(
                        TcpListenerStream::new(listener),
                        std::future::pending(),
                    )
                    .await;
            });
        });

        ScriptedCompiler {
            endpoint: format!("http://{addr}"),
            public_key,
            control,
        }
    }

    /// Endpoint of the scripted compiler (`http://127.0.0.1:<port>`).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Public key of the scripted compiler identity, in Display form, for
    /// tests that pin `compiler_public_key` in the node configuration.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Node compiler configuration pointing at this scripted compiler.
    pub fn node_config(&self) -> CompilerNodeConfig {
        CompilerNodeConfig {
            endpoints: vec![self.endpoint.clone()],
            api_key: Some(TEST_COMPILER_API_KEY.to_owned()),
            ..Default::default()
        }
    }

    /// Compile requests received so far: lets tests assert that no
    /// duplicate requests are sent while a compile is held.
    pub fn compiles_received(&self) -> u64 {
        self.control.compiles_received.load(Ordering::SeqCst)
    }

    /// Holds every compile response until `release` is called.
    pub fn hold(&self) {
        self.control.held.store(true, Ordering::SeqCst);
    }

    /// Unblocks held compile responses and stops holding new ones.
    pub fn release(&self) {
        self.control.held.store(false, Ordering::SeqCst);
        self.control.release.notify_waiters();
    }
}

/// gRPC service behind a [`ScriptedCompiler`].
struct ScriptedCompilerService {
    transform: ScriptedTransform,
    key_pair: KeyPair,
    toolchain_fingerprint: DigestIdentifier,
    control: Arc<ScriptedControl>,
    /// Responses by base64 source: the upstream artifact is fetched once
    /// and the transformed response is served identically afterwards.
    cache: Mutex<HashMap<String, pb::CompileResponse>>,
}

impl ScriptedCompilerService {
    /// Builds the signed attestation response for `wasm`, attesting the
    /// hashes of the requested source and the current manifest.
    fn build_response(
        &self,
        source_b64: &str,
        wasm: Vec<u8>,
    ) -> Result<pb::CompileResponse, Status> {
        let hash = HashAlgorithm::Blake3;
        let source_hash = hash_borsh(&*hash.hasher(), &source_b64.to_owned())
            .map_err(|e| {
            Status::internal(format!("failed to hash contract source: {e}"))
        })?;
        let manifest_hash =
            hash_borsh(&*hash.hasher(), &pipeline::compilation_toml())
                .map_err(|e| {
                    Status::internal(format!(
                        "failed to hash contract manifest: {e}"
                    ))
                })?;
        let wasm_hash = pipeline::hash_bytes(hash, &wasm, "scripted wasm")
            .map_err(|e| Status::internal(e.to_string()))?;

        let source_hash = source_hash.to_string();
        let manifest_hash = manifest_hash.to_string();
        let toolchain_fingerprint = self.toolchain_fingerprint.to_string();
        let wasm_hash = wasm_hash.to_string();

        let payload = borsh::to_vec(&(
            source_hash.clone(),
            manifest_hash.clone(),
            toolchain_fingerprint.clone(),
            wasm_hash.clone(),
        ))
        .map_err(|e| {
            Status::internal(format!(
                "failed to serialize attestation payload: {e}"
            ))
        })?;
        let signature = self.key_pair.sign(&payload).map_err(|e| {
            Status::internal(format!("failed to sign attestation: {e}"))
        })?;

        Ok(pb::CompileResponse {
            wasm,
            source_hash,
            manifest_hash,
            toolchain_fingerprint,
            wasm_hash,
            signature: signature.signature_bytes().to_vec(),
        })
    }
}

#[tonic::async_trait]
impl CompilerService for ScriptedCompilerService {
    async fn compile(
        &self,
        request: Request<pb::CompileRequest>,
    ) -> Result<Response<pb::CompileResponse>, Status> {
        let authorized = request
            .metadata()
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|key| key == TEST_COMPILER_API_KEY);
        if !authorized {
            return Err(Status::unauthenticated("invalid API key"));
        }

        self.control.compiles_received.fetch_add(1, Ordering::SeqCst);

        // Gate: while held, wait for release. The notified future is
        // created before re-checking the flag so no wakeup is missed.
        loop {
            let notified = self.control.release.notified();
            if !self.control.held.load(Ordering::SeqCst) {
                break;
            }
            notified.await;
        }

        let source_b64 = request.into_inner().source_b64;
        if let Some(response) = self.cache.lock().await.get(&source_b64) {
            return Ok(Response::new(response.clone()));
        }

        // Upstream: one real build through the embedded compiler (its
        // content-addressed store makes this a cache hit for sources the
        // suite already built).
        let client = CompilerClient::new(
            vec![embedded_compiler_endpoint().await],
            TEST_COMPILER_API_KEY.to_owned(),
            None,
            None,
            Some(Duration::from_secs(700)),
            None,
        );
        let outcome = client.compile(&source_b64).await.map_err(|e| {
            Status::internal(format!("scripted upstream compile failed: {e}"))
        })?;

        let wasm = match &self.transform {
            ScriptedTransform::Identity => outcome.wasm,
            ScriptedTransform::CustomSection(tag) => {
                append_custom_section(outcome.wasm, tag)
            }
        };
        let response = self.build_response(&source_b64, wasm)?;
        self.cache
            .lock()
            .await
            .insert(source_b64, response.clone());
        Ok(Response::new(response))
    }
}

/// Appends a custom section (id 0) named `ave-scripted-<tag>` at the end
/// of the module: valid per the wasm spec, ignored by engines, and it
/// changes the artifact bytes.
fn append_custom_section(mut wasm: Vec<u8>, tag: &str) -> Vec<u8> {
    let name = format!("ave-scripted-{tag}");
    let mut body = leb128_len(name.len());
    body.extend_from_slice(name.as_bytes());
    wasm.push(0x00);
    wasm.extend_from_slice(&leb128_len(body.len()));
    wasm.extend_from_slice(&body);
    wasm
}

/// Unsigned LEB128 encoding of a section/name length.
fn leb128_len(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}
