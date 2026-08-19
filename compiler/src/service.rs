//! gRPC compiler service: dedup, single-flight, bounded concurrency,
//! on-disk artifact store with LRU garbage collection and Ed25519
//! attestation signatures.

use std::collections::HashMap;
use std::future::Future;
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime};

use ave_common::compiler::pb;
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, KeyPair, KeyPairAlgorithm, hash_borsh,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::fs;
use tokio::sync::{Mutex, Semaphore};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::config::ServiceConfig;
use crate::error::CompilerError;
use crate::pipeline;

use pb::compiler_service_server::{CompilerService, CompilerServiceServer};

/// gRPC message size cap (encoding and decoding). Far above the maximum
/// source size and the expected wasm artifact sizes.
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

const ARTIFACT_WASM: &str = "contract.wasm";
const ARTIFACT_WASM_HASH: &str = "wasm.hash";
const CONTRACTS_SUBDIR: &str = "contracts";

/// Errors of the compiler service (configuration, identity, TLS, serving).
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("toolchain error: {0}")]
    Toolchain(String),

    #[error("io error [{path}]: {details}")]
    Io { path: String, details: String },

    #[error("store error: {0}")]
    Store(String),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("server error: {0}")]
    Server(String),
}

/// Result shared by every caller waiting on the same in-flight build.
type SharedBuild = Result<Arc<CompileArtifact>, Status>;

/// Role of a caller in the single-flight map: the leader builds and
/// publishes the outcome; followers wait on the shared watch channel.
enum Flight {
    Leader(tokio::sync::watch::Sender<Option<SharedBuild>>),
    Follower(tokio::sync::watch::Receiver<Option<SharedBuild>>),
}

/// Output of a single build: the wasm bytes and their digest.
struct CompileArtifact {
    wasm: Vec<u8>,
    wasm_hash: DigestIdentifier,
}

/// Content-addressed wasm artifact store with LRU garbage collection.
struct ArtifactStore {
    dir: PathBuf,
    max_bytes: u64,
    hash: HashAlgorithm,
    /// Last access per entry key; seeded from file mtimes at startup.
    last_access: Mutex<HashMap<String, SystemTime>>,
}

impl ArtifactStore {
    async fn new(
        dir: PathBuf,
        max_bytes: u64,
        hash: HashAlgorithm,
    ) -> Result<Self, ServiceError> {
        fs::create_dir_all(&dir).await.map_err(|e| ServiceError::Io {
            path: dir.to_string_lossy().to_string(),
            details: e.to_string(),
        })?;

        let mut last_access = HashMap::new();
        let mut entries =
            fs::read_dir(&dir).await.map_err(|e| ServiceError::Io {
                path: dir.to_string_lossy().to_string(),
                details: e.to_string(),
            })?;
        while let Some(entry) =
            entries.next_entry().await.map_err(|e| ServiceError::Io {
                path: dir.to_string_lossy().to_string(),
                details: e.to_string(),
            })?
        {
            let is_dir = match entry.file_type().await {
                Ok(file_type) => file_type.is_dir(),
                Err(_) => false,
            };
            if !is_dir {
                continue;
            }
            let key = entry.file_name().to_string_lossy().to_string();
            let accessed = entry
                .metadata()
                .await
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            last_access.insert(key, accessed);
        }

        Ok(Self {
            dir,
            max_bytes,
            hash,
            last_access: Mutex::new(last_access),
        })
    }

    /// Returns the stored artifact for `key`, verifying its integrity
    /// against the persisted hash. A missing, unreadable or corrupt entry
    /// is dropped and reported as a miss.
    async fn lookup(
        &self,
        key: &str,
    ) -> Result<Option<(Vec<u8>, DigestIdentifier)>, CompilerError> {
        let entry_dir = self.dir.join(key);
        let wasm_path = entry_dir.join(ARTIFACT_WASM);
        let wasm = match fs::read(&wasm_path).await {
            Ok(wasm) => wasm,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => {
                return Err(CompilerError::FileReadFailed {
                    path: wasm_path.to_string_lossy().to_string(),
                    details: error.to_string(),
                });
            }
        };

        let hash_path = entry_dir.join(ARTIFACT_WASM_HASH);
        let expected = match fs::read_to_string(&hash_path).await {
            Ok(expected) => expected,
            Err(error) => {
                warn!(
                    error = %error,
                    path = %hash_path.display(),
                    "Artifact store entry without hash file, dropping it"
                );
                self.remove_entry(key).await;
                return Ok(None);
            }
        };

        let wasm_hash =
            pipeline::hash_bytes(self.hash, &wasm, "artifact store wasm")?;
        if wasm_hash.to_string() != expected.trim() {
            warn!(
                expected = %expected.trim(),
                actual = %wasm_hash,
                path = %entry_dir.display(),
                "Artifact store entry hash mismatch, dropping it"
            );
            self.remove_entry(key).await;
            return Ok(None);
        }

        self.touch(key).await;
        Ok(Some((wasm, wasm_hash)))
    }

    /// Persists `wasm` under `key` together with its digest, then collects
    /// garbage if the store exceeds its size cap.
    async fn insert(
        &self,
        key: &str,
        wasm: &[u8],
    ) -> Result<DigestIdentifier, CompilerError> {
        let wasm_hash =
            pipeline::hash_bytes(self.hash, wasm, "artifact store wasm")?;

        let entry_dir = self.dir.join(key);
        fs::create_dir_all(&entry_dir).await.map_err(|e| {
            CompilerError::DirectoryCreationFailed {
                path: entry_dir.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let wasm_path = entry_dir.join(ARTIFACT_WASM);
        fs::write(&wasm_path, wasm).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: wasm_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let hash_path = entry_dir.join(ARTIFACT_WASM_HASH);
        fs::write(&hash_path, wasm_hash.to_string())
            .await
            .map_err(|e| CompilerError::FileWriteFailed {
                path: hash_path.to_string_lossy().to_string(),
                details: e.to_string(),
            })?;

        self.touch(key).await;
        self.collect_garbage().await?;

        Ok(wasm_hash)
    }

    /// Evicts least recently accessed entries while the store exceeds
    /// `max_bytes`.
    async fn collect_garbage(&self) -> Result<(), CompilerError> {
        let mut entries: Vec<(String, u64, SystemTime)> = Vec::new();
        let mut total: u64 = 0;

        let mut read_dir = fs::read_dir(&self.dir).await.map_err(|e| {
            CompilerError::FileReadFailed {
                path: self.dir.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;
        while let Some(entry) = read_dir.next_entry().await.map_err(|e| {
            CompilerError::FileReadFailed {
                path: self.dir.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })? {
            let is_dir = match entry.file_type().await {
                Ok(file_type) => file_type.is_dir(),
                Err(_) => false,
            };
            if !is_dir {
                continue;
            }
            let key = entry.file_name().to_string_lossy().to_string();
            let size = match fs::metadata(entry.path().join(ARTIFACT_WASM)).await
            {
                Ok(metadata) => metadata.len(),
                Err(_) => continue,
            };
            let accessed = {
                let last_access = self.last_access.lock().await;
                last_access.get(&key).copied()
            };
            let Some(accessed) = accessed else {
                continue;
            };
            total += size;
            entries.push((key, size, accessed));
        }

        if total <= self.max_bytes {
            return Ok(());
        }

        entries.sort_by_key(|(_, _, accessed)| *accessed);
        for (key, size, _) in entries {
            if total <= self.max_bytes {
                break;
            }
            let removed = fs::remove_dir_all(self.dir.join(&key)).await;
            match removed {
                Ok(()) => {
                    total = total.saturating_sub(size);
                    self.last_access.lock().await.remove(&key);
                    info!(key = %key, "Evicted artifact store entry");
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        key = %key,
                        "Failed to evict artifact store entry"
                    );
                }
            }
        }

        Ok(())
    }

    async fn remove_entry(&self, key: &str) {
        if let Err(error) = fs::remove_dir_all(self.dir.join(key)).await {
            debug!(
                error = %error,
                key = %key,
                "Failed to remove artifact store entry"
            );
        }
        self.last_access.lock().await.remove(key);
    }

    async fn touch(&self, key: &str) {
        self.last_access
            .lock()
            .await
            .insert(key.to_owned(), SystemTime::now());
    }
}

/// State shared by every clone of the gRPC service.
struct ServerState {
    config: ServiceConfig,
    hash: HashAlgorithm,
    manifest_hash: DigestIdentifier,
    toolchain_fingerprint: DigestIdentifier,
    key_pair: KeyPair,
    store: ArtifactStore,
    build_semaphore: Semaphore,
    queued_builds: AtomicUsize,
    in_flight:
        Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<SharedBuild>>>>,
    builds_completed: Arc<AtomicU64>,
}

/// gRPC compiler service. Cheap to clone (shares all state).
#[derive(Clone)]
pub struct CompilerServer {
    inner: Arc<ServerState>,
}

impl CompilerServer {
    /// Builds the service from its configuration: computes the toolchain
    /// fingerprint (fails to start when `rustc` is unusable), loads or
    /// generates the Ed25519 identity and scans the artifact store.
    pub async fn new(config: ServiceConfig) -> Result<Self, ServiceError> {
        config.validate()?;

        let hash = HashAlgorithm::Blake3;

        let toolchain_fingerprint = pipeline::toolchain_fingerprint(hash)
            .await
            .map_err(|e| ServiceError::Toolchain(e.to_string()))?;

        let manifest = pipeline::compilation_toml();
        let manifest_hash = hash_borsh(&*hash.hasher(), &manifest)
            .map_err(|e| ServiceError::Toolchain(e.to_string()))?;

        fs::create_dir_all(config.work_dir.join(CONTRACTS_SUBDIR))
            .await
            .map_err(|e| ServiceError::Io {
                path: config.work_dir.to_string_lossy().to_string(),
                details: e.to_string(),
            })?;

        let key_pair = load_or_generate_identity(&config.key_path).await?;

        let store = ArtifactStore::new(
            config.artifacts_dir.clone(),
            config.max_store_bytes,
            hash,
        )
        .await?;

        Ok(Self {
            inner: Arc::new(ServerState {
                build_semaphore: Semaphore::new(config.concurrent_builds()),
                queued_builds: AtomicUsize::new(0),
                in_flight: Mutex::new(HashMap::new()),
                builds_completed: Arc::new(AtomicU64::new(0)),
                config,
                hash,
                manifest_hash,
                toolchain_fingerprint,
                key_pair,
                store,
            }),
        })
    }

    /// Number of builds actually executed (not deduplicated, not cache
    /// hits). Exposed for tests and operational logging.
    pub fn build_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.inner.builds_completed)
    }

    /// Public key of the compiler identity, in its Display form; operators
    /// pin it in the node configuration to verify attestations.
    pub fn public_key(&self) -> String {
        self.inner.key_pair.public_key().to_string()
    }

    /// Serves the gRPC endpoint over an already bound listener until
    /// `shutdown` resolves.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ServiceError> {
        let local_addr = listener.local_addr().map_err(|e| {
            ServiceError::Server(format!(
                "failed to read listener address: {e}"
            ))
        })?;
        listener.set_nonblocking(true).map_err(|e| {
            ServiceError::Server(format!(
                "failed to set listener non-blocking: {e}"
            ))
        })?;
        let listener =
            tokio::net::TcpListener::from_std(listener).map_err(|e| {
                ServiceError::Server(format!(
                    "failed to convert listener: {e}"
                ))
            })?;

        let config = self.inner.config.clone();
        let tls = config.tls.clone();
        let api_keys = Arc::new(config.api_keys.clone());
        let inner = CompilerServiceServer::new(self)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);
        let service = tonic::service::interceptor::InterceptedService::new(
            inner,
            move |request: Request<()>| {
                let authorized = request
                    .metadata()
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|key| {
                        api_keys.iter().any(|valid| {
                            key.as_bytes().ct_eq(valid.as_bytes()).into()
                        })
                    });
                if authorized {
                    Ok(request)
                } else {
                    Err(Status::unauthenticated(
                        "missing or invalid API key",
                    ))
                }
            },
        );

        let mut builder = tonic::transport::Server::builder();
        if let Some(tls) = &tls {
            ensure_rustls_provider();
            let cert = fs::read(&tls.cert_pem_path).await.map_err(|e| {
                ServiceError::Tls(format!(
                    "failed to read certificate '{}': {e}",
                    tls.cert_pem_path.display()
                ))
            })?;
            let key = fs::read(&tls.key_pem_path).await.map_err(|e| {
                ServiceError::Tls(format!(
                    "failed to read private key '{}': {e}",
                    tls.key_pem_path.display()
                ))
            })?;
            builder = builder
                .tls_config(
                    ServerTlsConfig::new()
                        .identity(Identity::from_pem(cert, key)),
                )
                .map_err(|e| {
                    ServiceError::Tls(format!("invalid TLS material: {e}"))
                })?;
        }

        info!(
            addr = %local_addr,
            tls = tls.is_some(),
            max_concurrent_builds = config.concurrent_builds(),
            max_queued_builds = config.max_queued_builds,
            max_source_bytes = config.max_source_bytes,
            max_store_bytes = config.max_store_bytes,
            artifacts_dir = %config.artifacts_dir.display(),
            work_dir = %config.work_dir.display(),
            api_keys = config.api_keys.len(),
            "Compiler service listening"
        );

        builder
            .add_service(service)
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                shutdown,
            )
            .await
            .map_err(|e| ServiceError::Server(e.to_string()))
    }

    /// Builds and stores the artifact for `key`, bounded by the global
    /// build semaphore and the queue cap.
    async fn build_and_store(
        &self,
        key: &str,
        source_b64: &str,
    ) -> Result<CompileArtifact, Status> {
        let permit = match self.inner.build_semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                let queued = self.inner.queued_builds.fetch_add(1, Ordering::SeqCst) + 1;
                if queued > self.inner.config.max_queued_builds {
                    self.inner.queued_builds.fetch_sub(1, Ordering::SeqCst);
                    return Err(Status::resource_exhausted(
                        "build queue is full",
                    ));
                }
                debug!(
                    key = %key,
                    queued = queued,
                    "Build waiting for a build slot"
                );
                let permit = self
                    .inner
                    .build_semaphore
                    .acquire()
                    .await
                    .map_err(|_| Status::internal("build semaphore closed"));
                self.inner.queued_builds.fetch_sub(1, Ordering::SeqCst);
                permit?
            }
        };

        let started_at = Instant::now();
        let result = self.build_once(key, source_b64).await;
        drop(permit);

        match &result {
            Ok(_) => {
                self.inner.builds_completed.fetch_add(1, Ordering::SeqCst);
                info!(
                    key = %key,
                    elapsed_ms = started_at.elapsed().as_millis() as u64,
                    "Contract build completed"
                );
            }
            Err(status) => {
                warn!(
                    key = %key,
                    code = %status.code(),
                    message = %status.message(),
                    elapsed_ms = started_at.elapsed().as_millis() as u64,
                    "Contract build failed"
                );
            }
        }

        result
    }

    /// Runs the cargo build in a per-job directory and inserts the
    /// artifact into the store.
    async fn build_once(
        &self,
        key: &str,
        source_b64: &str,
    ) -> Result<CompileArtifact, Status> {
        // Per-job build directory under <work_dir>/contracts/<key>: the
        // pipeline derives the contracts root (and the optional vendor
        // directory at <work_dir>/vendor) from this layout.
        let build_dir = self
            .inner
            .config
            .work_dir
            .join(CONTRACTS_SUBDIR)
            .join(key);

        // Drop leftovers of a previous crashed attempt with the same key.
        let _ = fs::remove_dir_all(&build_dir).await;

        let build_result = pipeline::build_wasm(source_b64, &build_dir).await;

        if let Err(error) = fs::remove_dir_all(&build_dir).await {
            warn!(
                error = %error,
                path = %build_dir.display(),
                "Failed to remove contract build directory"
            );
        }

        let wasm = build_result.map_err(|e| status_for_build_error(&e))?;

        let wasm_hash = self
            .inner
            .store
            .insert(key, &wasm)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(CompileArtifact { wasm, wasm_hash })
    }

    /// Builds the signed attestation response.
    fn build_response(
        &self,
        wasm: Vec<u8>,
        source_hash: &DigestIdentifier,
        wasm_hash: &DigestIdentifier,
    ) -> Result<pb::CompileResponse, Status> {
        let source_hash = source_hash.to_string();
        let manifest_hash = self.inner.manifest_hash.to_string();
        let toolchain_fingerprint =
            self.inner.toolchain_fingerprint.to_string();
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

        let signature = self.inner.key_pair.sign(&payload).map_err(|e| {
            Status::internal(format!(
                "failed to sign attestation: {e}"
            ))
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
impl CompilerService for CompilerServer {
    async fn compile(
        &self,
        request: Request<pb::CompileRequest>,
    ) -> Result<Response<pb::CompileResponse>, Status> {
        let started_at = Instant::now();
        let source_b64 = request.into_inner().source_b64;

        if source_b64.len() > self.inner.config.max_source_bytes {
            return Err(Status::invalid_argument(format!(
                "source exceeds the maximum of {} bytes",
                self.inner.config.max_source_bytes
            )));
        }

        let hash = self.inner.hash;
        let source_hash =
            hash_borsh(&*hash.hasher(), &source_b64).map_err(|e| {
                Status::internal(format!(
                    "failed to hash contract source: {e}"
                ))
            })?;
        let key = format!(
            "{}_{}_{}",
            source_hash,
            self.inner.manifest_hash,
            self.inner.toolchain_fingerprint
        );

        match self.inner.store.lookup(&key).await {
            Ok(Some((wasm, wasm_hash))) => {
                info!(
                    key = %key,
                    elapsed_ms = started_at.elapsed().as_millis() as u64,
                    "Contract cache hit"
                );
                let response =
                    self.build_response(wasm, &source_hash, &wasm_hash)?;
                return Ok(Response::new(response));
            }
            Ok(None) => {
                debug!(key = %key, "Contract cache miss");
            }
            Err(error) => {
                warn!(
                    error = %error,
                    key = %key,
                    "Artifact store lookup failed, rebuilding"
                );
            }
        }

        // Single-flight: the first caller for a key builds; the rest wait
        // on the same outcome. The leader always publishes a result (Ok
        // or the mapped Status) before removing the entry, so followers
        // never wait indefinitely.
        let flight = {
            let mut in_flight = self.inner.in_flight.lock().await;
            match in_flight.entry(key.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => {
                    Flight::Follower(entry.get().clone())
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let (sender, receiver) =
                        tokio::sync::watch::channel(None);
                    entry.insert(receiver);
                    Flight::Leader(sender)
                }
            }
        };

        let shared = match flight {
            Flight::Leader(sender) => {
                let outcome = self
                    .build_and_store(&key, &source_b64)
                    .await
                    .map(Arc::new);
                let _ = sender.send(Some(outcome.clone()));
                self.inner.in_flight.lock().await.remove(&key);
                outcome
            }
            Flight::Follower(mut receiver) => {
                let published = receiver
                    .wait_for(|value| value.is_some())
                    .await
                    .map_err(|_| {
                        Status::internal("build leader dropped its result")
                    })?;
                match published.clone() {
                    Some(shared) => shared,
                    None => {
                        return Err(Status::internal(
                            "build finished without a result",
                        ));
                    }
                }
            }
        };

        let artifact = shared?;
        let response = self.build_response(
            artifact.wasm.clone(),
            &source_hash,
            &artifact.wasm_hash,
        )?;
        Ok(Response::new(response))
    }
}

/// Maps a pipeline error to the gRPC status of the build: contract
/// problems are INVALID_ARGUMENT (the node reports them as contract
/// failures), everything else is INTERNAL. `CargoBuildFailed` means the
/// cargo process could not even run — a service misconfiguration, not a
/// contract problem — so it is INTERNAL like any other infra failure.
fn status_for_build_error(error: &CompilerError) -> Status {
    match error {
        CompilerError::Base64DecodeFailed { .. } => {
            Status::invalid_argument(error.to_string())
        }
        CompilerError::CompilationFailed | CompilerError::BuildTimeout { .. } => {
            Status::invalid_argument(
                format!("contract does not compile: {error}"),
            )
        }
        _ => Status::internal(error.to_string()),
    }
}

/// Loads the compiler Ed25519 identity (unencrypted PKCS#8 DER), or
/// generates and persists a fresh one on first start. Private key files
/// are owner-only (0o600); more permissive existing files are tightened
/// on read, following the node key policy.
async fn load_or_generate_identity(
    key_path: &Path,
) -> Result<KeyPair, ServiceError> {
    let read_result = fs::read(key_path).await;
    match read_result {
        Ok(bytes) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = fs::metadata(key_path).await
                    && metadata.permissions().mode() & 0o077 != 0
                {
                    fs::set_permissions(
                        key_path,
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .await
                    .map_err(|e| ServiceError::Identity(format!(
                        "cannot tighten permissions of '{}': {e}",
                        key_path.display()
                    )))?;
                }
            }
            KeyPair::from_secret_der(&bytes).map_err(|e| {
                ServiceError::Identity(format!(
                    "failed to load identity from '{}': {e}",
                    key_path.display()
                ))
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key_pair = KeyPair::generate(KeyPairAlgorithm::Ed25519)
                .map_err(|e| {
                    ServiceError::Identity(format!(
                        "failed to generate identity: {e}"
                    ))
                })?;
            let der = key_pair.to_secret_der().map_err(|e| {
                ServiceError::Identity(format!(
                    "failed to serialize identity: {e}"
                ))
            })?;

            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    ServiceError::Io {
                        path: parent.to_string_lossy().to_string(),
                        details: e.to_string(),
                    }
                })?;
            }

            // Atomic write: a crash mid-write must not leave a corrupt
            // identity behind.
            let tmp_path = key_path.with_extension("der.tmp");
            fs::write(&tmp_path, &der).await.map_err(|e| {
                ServiceError::Io {
                    path: tmp_path.to_string_lossy().to_string(),
                    details: e.to_string(),
                }
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &tmp_path,
                    std::fs::Permissions::from_mode(0o600),
                )
                .await
                .map_err(|e| ServiceError::Io {
                    path: tmp_path.to_string_lossy().to_string(),
                    details: e.to_string(),
                })?;
            }
            fs::rename(&tmp_path, key_path).await.map_err(|e| {
                ServiceError::Io {
                    path: key_path.to_string_lossy().to_string(),
                    details: e.to_string(),
                }
            })?;

            info!(
                path = %key_path.display(),
                "Generated new compiler identity"
            );
            Ok(key_pair)
        }
        Err(error) => Err(ServiceError::Io {
            path: key_path.to_string_lossy().to_string(),
            details: error.to_string(),
        }),
    }
}

/// Installs the process-level rustls crypto provider that tonic resolves
/// when TLS is in use. A no-op when the embedding application already
/// installed one.
fn ensure_rustls_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
