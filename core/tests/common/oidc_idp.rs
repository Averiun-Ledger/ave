//! Mock OIDC identity provider for Kafka OAUTHBEARER integration tests.
//!
//! This is NOT a stub: it issues real RS256-signed JWTs (RSA-2048 keypair
//! generated per run with aws-lc-rs) and serves a real OIDC discovery
//! document and JWKS endpoint, so a broker (Redpanda) validates the tokens
//! exactly as it would against a production IdP. RS256 because Redpanda's
//! JWKS verifier only accepts RSA keys.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{self, KeyPair as _, RsaKeyPair};
use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

const KEY_ID: &str = "oidc-test-key";

struct IdpState {
    issuer: String,
    audience: String,
    key_pair: RsaKeyPair,
    /// Base64url of the RSA public key components (modulus, exponent).
    jwk_n: String,
    jwk_e: String,
    hits: IdpHits,
}

/// Requests received by each endpoint; lets a failing test tell apart
/// "the broker never reached the IdP" from "the broker rejected the token".
#[derive(Clone, Debug, Default)]
pub struct IdpHits {
    discovery: Arc<AtomicUsize>,
    jwks: Arc<AtomicUsize>,
    token: Arc<AtomicUsize>,
}

impl IdpHits {
    pub fn discovery(&self) -> usize {
        self.discovery.load(Ordering::Relaxed)
    }

    pub fn jwks(&self) -> usize {
        self.jwks.load(Ordering::Relaxed)
    }

    pub fn token(&self) -> usize {
        self.token.load(Ordering::Relaxed)
    }

    fn bump(field: &Arc<AtomicUsize>) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Sign a JWT (RS256) with the given claims.
fn sign_jwt(state: &IdpState, subject: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    let header = b64url(
        serde_json::to_string(&json!({
            "alg": "RS256",
            "kid": KEY_ID,
            "typ": "JWT",
        }))
        .expect("header serializes")
        .as_bytes(),
    );
    let payload = b64url(
        serde_json::to_string(&json!({
            "iss": state.issuer,
            "sub": subject,
            "aud": state.audience,
            "iat": now,
            "exp": now + 3_600,
        }))
        .expect("payload serializes")
        .as_bytes(),
    );
    let message = format!("{header}.{payload}");
    let rng = SystemRandom::new();
    let mut signature = vec![0u8; state.key_pair.public_modulus_len()];
    state
        .key_pair
        .sign(
            &signature::RSA_PKCS1_SHA256,
            &rng,
            message.as_bytes(),
            &mut signature,
        )
        .expect("RSA signing cannot fail with a valid key");
    format!("{message}.{}", b64url(&signature))
}

async fn discovery(State(state): State<Arc<IdpState>>) -> Json<Value> {
    IdpHits::bump(&state.hits.discovery);
    Json(json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/jwks", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "grant_types_supported": ["client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }))
}

async fn jwks(State(state): State<Arc<IdpState>>) -> Json<Value> {
    IdpHits::bump(&state.hits.jwks);
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KEY_ID,
            "n": state.jwk_n,
            "e": state.jwk_e,
        }],
    }))
}

async fn token(
    State(state): State<Arc<IdpState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    IdpHits::bump(&state.hits.token);
    let subject = body
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    Json(json!({
        "access_token": sign_jwt(&state, &subject),
        "token_type": "Bearer",
        "expires_in": 3_600,
    }))
}

/// A running mock IdP bound to all interfaces, so both the test process and
/// the Redpanda container (via `host.docker.internal`) can reach it.
pub struct MockOidcIdp {
    /// Issuer URL as seen from the broker container.
    pub issuer: String,
    /// Token endpoint URL for the producer running on the host.
    pub token_url: String,
    /// Audience claim the broker expects.
    pub audience: String,
    hits: IdpHits,
    handle: tokio::task::JoinHandle<()>,
}

impl MockOidcIdp {
    /// Start the IdP on a free port. `host_for_broker` is how the broker
    /// container reaches this host (e.g. `host.docker.internal`).
    pub async fn start(host_for_broker: &str, audience: &str) -> Self {
        let key_pair = RsaKeyPair::generate(KeySize::Rsa2048)
            .expect("RSA-2048 keypair generation should succeed");
        let public_key = key_pair.public_key();
        let jwk_n =
            b64url(public_key.modulus().big_endian_without_leading_zero());
        let jwk_e =
            b64url(public_key.exponent().big_endian_without_leading_zero());

        let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .expect("IdP should bind an ephemeral port");
        let addr = listener.local_addr().expect("listener has local address");
        let issuer = format!("http://{host_for_broker}:{}", addr.port());
        let token_url = format!("http://127.0.0.1:{}/token", addr.port());

        let hits = IdpHits::default();
        let state = Arc::new(IdpState {
            issuer: issuer.clone(),
            audience: audience.to_owned(),
            key_pair,
            jwk_n,
            jwk_e,
            hits: hits.clone(),
        });
        let app = axum::Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(state);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            issuer,
            token_url,
            audience: audience.to_owned(),
            hits,
            handle,
        }
    }

    /// Requests received so far per endpoint.
    pub fn hits(&self) -> &IdpHits {
        &self.hits
    }
}

impl Drop for MockOidcIdp {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
