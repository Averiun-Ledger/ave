//! gRPC client of the compiler service, used by the node.
//!
//! Ordered failover across the configured endpoints with a per-attempt
//! timeout; every response is verified before use: expected toolchain,
//! attestation signature (when the compiler public key is pinned), wasm
//! integrity against its attested hash, and an opportunistic cross-check
//! that alarms when two compilers disagree on the same artifact.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use ave_common::compiler::pb;
use ave_common::identity::{
    DSAlgorithm, DigestIdentifier, HashAlgorithm, PublicKey,
    SignatureIdentifier, hash_borsh,
};
use tokio::sync::Mutex;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, Request};
use tracing::{debug, error, warn};

use crate::error::CompilerError;
use crate::pipeline;

use pb::compiler_service_client::CompilerServiceClient;

/// Default per-attempt timeout (builds are long; cache hits and
/// single-flight followers answer immediately).
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// gRPC message size cap; mirrors the server side.
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Verified result of a remote compilation.
#[derive(Debug, Clone)]
pub struct CompileOutcome {
    pub wasm: Vec<u8>,
    pub source_hash: DigestIdentifier,
    pub manifest_hash: DigestIdentifier,
    pub toolchain_fingerprint: DigestIdentifier,
    pub wasm_hash: DigestIdentifier,
}

/// Client of the compiler service pool.
pub struct CompilerClient {
    endpoints: Vec<String>,
    api_key: String,
    expected_toolchain: Option<DigestIdentifier>,
    compiler_public_key: Option<PublicKey>,
    request_timeout: Duration,
    pinned_cert_pem: Option<String>,
    hash: HashAlgorithm,
    /// wasm hash already seen per `(source, manifest, toolchain)` key, for
    /// the opportunistic cross-check.
    seen: Mutex<HashMap<String, DigestIdentifier>>,
    /// Toolchain fingerprint of the last successful compile.
    last_toolchain: Mutex<Option<DigestIdentifier>>,
}

/// Outcome of a single endpoint attempt.
enum Attempt {
    /// Verified response.
    Success(CompileOutcome),
    /// Endpoint unusable for this call (transport, timeout, auth,
    /// protocol violation): try the next one.
    Failed(String),
    /// The contract was rejected (does not compile, too large). This is
    /// deterministic across the pool: no failover.
    ContractRejected(String),
    /// The compiler runs a different toolchain than pinned.
    ToolchainMismatch { actual: String },
    /// The attestation did not verify (bad signature or tampered wasm).
    InvalidAttestation(String),
    /// Two compilers disagree on the same artifact: alarm, no failover.
    CrossCheckMismatch { expected: String, actual: String },
}

impl CompilerClient {
    /// Builds a client of the compiler pool. `expected_toolchain`,
    /// `compiler_public_key` and `pinned_cert_pem` are the optional
    /// trust anchors of the node configuration; `request_timeout`
    /// defaults to 120 seconds.
    pub fn new(
        endpoints: Vec<String>,
        api_key: String,
        expected_toolchain: Option<DigestIdentifier>,
        compiler_public_key: Option<PublicKey>,
        request_timeout: Option<Duration>,
        pinned_cert_pem: Option<String>,
    ) -> Self {
        Self {
            endpoints,
            api_key,
            expected_toolchain,
            compiler_public_key,
            request_timeout: request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
            pinned_cert_pem,
            hash: HashAlgorithm::Blake3,
            seen: Mutex::new(HashMap::new()),
            last_toolchain: Mutex::new(None),
        }
    }

    /// Toolchain fingerprint pinned in the configuration, when any.
    pub fn expected_toolchain(&self) -> Option<DigestIdentifier> {
        self.expected_toolchain.clone()
    }

    /// Toolchain fingerprint of the last successful compile, when any.
    pub async fn last_toolchain(&self) -> Option<DigestIdentifier> {
        self.last_toolchain.lock().await.clone()
    }

    /// Compiles `source_b64` in the compiler pool, failing over in order
    /// and verifying the attestation of the winning response.
    pub async fn compile(
        &self,
        source_b64: &str,
    ) -> Result<CompileOutcome, CompilerError> {
        let api_key = MetadataValue::from_str(&self.api_key).map_err(|e| {
            CompilerError::CompilersUnavailable {
                details: format!("invalid API key metadata value: {e}"),
            }
        })?;

        let mut failures: Vec<String> = Vec::new();
        let mut toolchain_mismatch: Option<String> = None;
        let mut invalid_attestation = false;

        for endpoint in &self.endpoints {
            match self.attempt(endpoint, &api_key, source_b64).await {
                Attempt::Success(outcome) => {
                    *self.last_toolchain.lock().await =
                        Some(outcome.toolchain_fingerprint.clone());
                    return Ok(outcome);
                }
                Attempt::Failed(reason) => {
                    warn!(
                        endpoint = %endpoint,
                        reason = %reason,
                        "Compiler endpoint failed, trying next"
                    );
                    failures.push(format!("{endpoint}: {reason}"));
                }
                Attempt::ContractRejected(reason) => {
                    return Err(CompilerError::ContractCheckFailed {
                        error: reason,
                    });
                }
                Attempt::ToolchainMismatch { actual } => {
                    warn!(
                        endpoint = %endpoint,
                        actual = %actual,
                        "Compiler endpoint toolchain mismatch, trying next"
                    );
                    toolchain_mismatch = Some(actual);
                }
                Attempt::InvalidAttestation(reason) => {
                    warn!(
                        endpoint = %endpoint,
                        reason = %reason,
                        "Compiler endpoint attestation invalid, trying next"
                    );
                    invalid_attestation = true;
                    failures.push(format!("{endpoint}: {reason}"));
                }
                Attempt::CrossCheckMismatch { expected, actual } => {
                    return Err(CompilerError::AttestationMismatch {
                        expected,
                        actual,
                    });
                }
            }
        }

        // Final error precedence: attestation failures (possible tampering)
        // over toolchain drift over plain unavailability.
        if invalid_attestation {
            return Err(CompilerError::InvalidAttestationSignature);
        }
        if let (Some(expected), Some(actual)) =
            (&self.expected_toolchain, toolchain_mismatch)
        {
            return Err(CompilerError::ToolchainMismatch {
                expected: expected.to_string(),
                actual,
            });
        }
        Err(CompilerError::CompilersUnavailable {
            details: failures.join("; "),
        })
    }

    /// Single endpoint attempt: connect, compile and verify the response.
    async fn attempt(
        &self,
        endpoint: &str,
        api_key: &MetadataValue<tonic::metadata::Ascii>,
        source_b64: &str,
    ) -> Attempt {
        let channel = match self.connect(endpoint).await {
            Ok(channel) => channel,
            Err(reason) => return Attempt::Failed(reason),
        };

        let mut client = CompilerServiceClient::new(channel)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES);

        let mut request = Request::new(pb::CompileRequest {
            source_b64: source_b64.to_owned(),
        });
        request.metadata_mut().insert("x-api-key", api_key.clone());

        let response = match client.compile(request).await {
            Ok(response) => response.into_inner(),
            Err(status) => match status.code() {
                // Contract problems are deterministic across the pool:
                // failing over would just rebuild the same failure.
                Code::InvalidArgument => {
                    debug!(
                        endpoint = %endpoint,
                        message = %status.message(),
                        "Compiler rejected the contract"
                    );
                    return Attempt::ContractRejected(
                        status.message().to_owned(),
                    );
                }
                _ => {
                    return Attempt::Failed(format!(
                        "compile failed with status {}: {}",
                        status.code(),
                        status.message()
                    ));
                }
            },
        };

        self.verify(endpoint, source_b64, response).await
    }

    /// Verification chain applied to every OK response before accepting
    /// it: hash parsing, source/manifest echo, expected toolchain, wasm
    /// integrity, attestation signature and the cross-check.
    async fn verify(
        &self,
        endpoint: &str,
        source_b64: &str,
        response: pb::CompileResponse,
    ) -> Attempt {
        let parse = |value: &str, field: &'static str| {
            DigestIdentifier::from_str(value).map_err(|e| {
                Attempt::Failed(format!("unparseable {field} '{value}': {e}"))
            })
        };
        let source_hash = match parse(&response.source_hash, "source_hash") {
            Ok(hash) => hash,
            Err(attempt) => return attempt,
        };
        let manifest_hash =
            match parse(&response.manifest_hash, "manifest_hash") {
                Ok(hash) => hash,
                Err(attempt) => return attempt,
            };
        let toolchain_fingerprint = match parse(
            &response.toolchain_fingerprint,
            "toolchain_fingerprint",
        ) {
            Ok(hash) => hash,
            Err(attempt) => return attempt,
        };
        let wasm_hash = match parse(&response.wasm_hash, "wasm_hash") {
            Ok(hash) => hash,
            Err(attempt) => return attempt,
        };

        // The response must attest the exact content requested.
        let local_source_hash =
            match hash_borsh(&*self.hash.hasher(), &source_b64.to_owned()) {
                Ok(hash) => hash,
                Err(e) => {
                    return Attempt::Failed(format!(
                        "failed to hash contract source: {e}"
                    ));
                }
            };
        let manifest = pipeline::compilation_toml();
        let local_manifest_hash =
            match hash_borsh(&*self.hash.hasher(), &manifest) {
                Ok(hash) => hash,
                Err(e) => {
                    return Attempt::Failed(format!(
                        "failed to hash contract manifest: {e}"
                    ));
                }
            };
        if source_hash != local_source_hash
            || manifest_hash != local_manifest_hash
        {
            return Attempt::InvalidAttestation(
                "response hashes do not match the requested source".to_owned(),
            );
        }

        if let Some(expected) = &self.expected_toolchain
            && toolchain_fingerprint != *expected
        {
            return Attempt::ToolchainMismatch {
                actual: toolchain_fingerprint.to_string(),
            };
        }

        // Integrity in transit: the bytes must match the attested hash.
        let local_wasm_hash = match pipeline::hash_bytes(
            self.hash,
            &response.wasm,
            "compiler response wasm",
        ) {
            Ok(hash) => hash,
            Err(e) => {
                return Attempt::Failed(format!(
                    "failed to hash response wasm: {e}"
                ));
            }
        };
        if local_wasm_hash != wasm_hash {
            return Attempt::InvalidAttestation(format!(
                "wasm hash mismatch: attested {}, computed {}",
                wasm_hash, local_wasm_hash
            ));
        }

        if let Some(public_key) = &self.compiler_public_key {
            let payload = match borsh::to_vec(&(
                response.source_hash.clone(),
                response.manifest_hash.clone(),
                response.toolchain_fingerprint.clone(),
                response.wasm_hash.clone(),
            )) {
                Ok(payload) => payload,
                Err(e) => {
                    return Attempt::Failed(format!(
                        "failed to serialize attestation payload: {e}"
                    ));
                }
            };
            let signature = match SignatureIdentifier::new(
                DSAlgorithm::Ed25519,
                response.signature.clone(),
            ) {
                Ok(signature) => signature,
                Err(e) => {
                    return Attempt::InvalidAttestation(format!(
                        "malformed attestation signature: {e}"
                    ));
                }
            };
            if let Err(e) = public_key.verify(&payload, &signature) {
                return Attempt::InvalidAttestation(format!(
                    "attestation signature verification failed: {e}"
                ));
            }
        }

        // Opportunistic cross-check: two compilers must never disagree on
        // the artifact of the same (source, manifest, toolchain). This is
        // an alarm, not a failover: honest disagreement is impossible with
        // reproducible builds.
        let key =
            format!("{source_hash}_{manifest_hash}_{toolchain_fingerprint}");
        {
            let mut seen = self.seen.lock().await;
            if let Some(previous) = seen.get(&key)
                && *previous != wasm_hash
            {
                error!(
                    endpoint = %endpoint,
                    key = %key,
                    expected = %previous,
                    actual = %wasm_hash,
                    "Compiler attestation mismatch: compilers disagree on \
                     the same artifact; possible drift, non-determinism \
                     or malice"
                );
                let expected = previous.to_string();
                let actual = wasm_hash.to_string();
                drop(seen);
                return Attempt::CrossCheckMismatch { expected, actual };
            }
            seen.insert(key, wasm_hash.clone());
        }

        Attempt::Success(CompileOutcome {
            wasm: response.wasm,
            source_hash,
            manifest_hash,
            toolchain_fingerprint,
            wasm_hash,
        })
    }

    /// Connects to one endpoint; `https://` endpoints use TLS with the
    /// pinned certificate when configured, native roots otherwise.
    async fn connect(&self, endpoint: &str) -> Result<Channel, String> {
        let mut endpoint = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|e| format!("invalid endpoint: {e}"))?;
        endpoint = endpoint
            .connect_timeout(self.request_timeout)
            .timeout(self.request_timeout);

        if endpoint.uri().scheme_str() == Some("https") {
            ensure_rustls_provider();
            let tls = match &self.pinned_cert_pem {
                Some(pem) => ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(pem.clone())),
                None => ClientTlsConfig::new().with_native_roots(),
            };
            endpoint = endpoint
                .tls_config(tls)
                .map_err(|e| format!("TLS configuration failed: {e}"))?;
        }

        endpoint
            .connect()
            .await
            .map_err(|e| format!("connect failed: {e}"))
    }
}

/// Installs the process-level rustls crypto provider that tonic resolves
/// when TLS is in use. A no-op when the embedding application already
/// installed one.
fn ensure_rustls_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
