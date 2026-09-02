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

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::OnceCell;

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
