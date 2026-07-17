use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    auth::{self, AuthDatabase},
    logging,
    middleware::tower_trace,
    self_signed_cert::{
        CertPaths, cert_needs_renewal, cert_renewal_task,
        generate_self_signed_cert,
    },
    server::build_routes,
};
use ave_bridge::{
    Bridge,
    clap::Parser,
    config::Config as BridgeConfig,
    settings::{
        build_config,
        command::{
            Args, build_auth_password, build_config_path, build_key_password,
            build_safe_mode, build_sink_api_key, build_sink_password,
        },
    },
};
use axum::{
    BoxError, Router,
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header,
        uri::{Authority, Scheme},
    },
    response::{IntoResponse, Redirect},
    routing::any,
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use futures::future::join_all;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::{
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
};
use tracing::{error, info, warn};

const TARGET: &str = "ave::http";

#[derive(Clone)]
struct Ports {
    http: String,
    https: String,
}

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("failed to load configuration from '{path}': {message}")]
    ConfigLoad { path: String, message: String },

    #[error("failed to bind HTTP listener on {address}: {message}")]
    HttpBind { address: String, message: String },

    #[error("invalid CORS configuration: {0}")]
    CorsConfig(String),

    #[error("invalid proxy configuration: {0}")]
    ProxyConfig(String),

    #[error("failed to initialize authentication: {0}")]
    AuthInit(String),

    #[error("failed to build bridge: {0}")]
    BridgeBuild(String),

    #[error("invalid HTTPS listen address '{address}': {message}")]
    HttpsAddress { address: String, message: String },

    #[error("HTTPS is enabled but no certificate path is configured")]
    MissingHttpsCertPath,

    #[error("HTTPS is enabled but no private key path is configured")]
    MissingHttpsKeyPath,

    #[error("failed to generate self-signed certificate: {0}")]
    SelfSignedCert(String),

    #[error("failed to load TLS certificate/key: {0}")]
    TlsConfig(String),

    #[error("HTTP server failed: {0}")]
    HttpServer(String),

    #[error("HTTPS server failed: {0}")]
    HttpsServer(String),

    #[error("fatal internal runner signalled process restart")]
    FatalCrashSignal,

    #[error("failed to inspect HTTP listener: {0}")]
    Listener(String),

    #[error("HTTP to HTTPS redirect server failed: {0}")]
    RedirectServer(String),

    #[error("directory or permission validation failed: {0}")]
    DirectoryValidation(String),
}

struct ResolvedSecret {
    value: String,
    source: &'static str,
}

impl ResolvedSecret {
    const fn is_set(&self) -> bool {
        !self.value.is_empty()
    }
}

struct StartupSecrets {
    auth_password: ResolvedSecret,
    key_password: ResolvedSecret,
    sink_password: ResolvedSecret,
    sink_api_key: ResolvedSecret,
}

fn resolve_secret(
    cli_value: String,
    env_provider: fn() -> String,
) -> ResolvedSecret {
    if !cli_value.is_empty() {
        ResolvedSecret {
            value: cli_value,
            source: "cli",
        }
    } else {
        let env_value = env_provider();
        if !env_value.is_empty() {
            ResolvedSecret {
                value: env_value,
                source: "env",
            }
        } else {
            ResolvedSecret {
                value: String::new(),
                source: "default",
            }
        }
    }
}

fn log_effective_configuration(
    config_path: &str,
    config: &BridgeConfig,
    secrets: &StartupSecrets,
) {
    info!(target: TARGET, "--- configuration ---");
    info!(target: TARGET, "[runtime]");
    if config_path.is_empty() {
        info!(target: TARGET, "  config    : default (built-in)");
    } else {
        info!(target: TARGET, "  config    : {}", config_path);
    }
    info!(target: TARGET, "  safe mode : {}", config.node.safe_mode);

    info!(target: TARGET, "[secrets]");
    info!(
        target: TARGET,
        "  auth pass : {} ({})",
        secrets.auth_password.source,
        if secrets.auth_password.is_set() {
            "set"
        } else {
            "missing"
        }
    );
    info!(
        target: TARGET,
        "  key pass  : {} ({})",
        secrets.key_password.source,
        if secrets.key_password.is_set() {
            "set"
        } else {
            "missing"
        }
    );
    info!(
        target: TARGET,
        "  sink pass : {} ({})",
        secrets.sink_password.source,
        if secrets.sink_password.is_set() {
            "set"
        } else {
            "missing"
        }
    );
    info!(
        target: TARGET,
        "  sink apikey: {} ({})",
        secrets.sink_api_key.source,
        if secrets.sink_api_key.is_set() {
            "set"
        } else {
            "missing"
        }
    );

    match config_log_sections(config) {
        Ok(sections) => {
            for (section, lines) in &sections {
                info!(target: TARGET, "[{section}]");
                for line in lines {
                    info!(target: TARGET, "  {line}");
                }
            }
        }
        Err(e) => {
            warn!(
                target: TARGET,
                "  failed to serialize configuration for logging: {e}"
            );
        }
    }

    info!(target: TARGET, "--- end ---");
}

/// Config keys whose values must never appear in logs. Non-empty values are
/// replaced with `"***"`; empty values are kept so "not configured" stays
/// visible. (`api_key` is already redacted by `SinkAuthConfig` itself; the
/// rest are redacted here.)
const REDACTED_CONFIG_KEYS: [&str; 3] = ["api_key", "password", "superadmin"];

/// Builds the effective-configuration dump: one `(section, lines)` pair per
/// top-level configuration section, with every parameter flattened into a
/// `dotted.path: value` line. It is built from the serialized configuration,
/// so parameters added to the config types are logged automatically;
/// sensitive values (see [`REDACTED_CONFIG_KEYS`]) are redacted first.
fn config_log_sections(
    config: &BridgeConfig,
) -> Result<Vec<(String, Vec<String>)>, serde_json::Error> {
    let mut value = serde_json::to_value(config)?;
    redact_sensitive_values(&mut value);
    let mut sections = Vec::new();
    if let serde_json::Value::Object(map) = &value {
        for (section, section_value) in map {
            let mut lines = Vec::new();
            flatten_config_value(section_value, section.clone(), &mut lines);
            sections.push((section.clone(), lines));
        }
    }
    Ok(sections)
}

/// Replaces the values of [`REDACTED_CONFIG_KEYS`] with `"***"`, recursively.
fn redact_sensitive_values(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                if REDACTED_CONFIG_KEYS.contains(&key.as_str())
                    && matches!(
                        entry,
                        serde_json::Value::String(s) if !s.is_empty()
                    )
                {
                    *entry = serde_json::Value::String("***".to_string());
                } else {
                    redact_sensitive_values(entry);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_sensitive_values(item);
            }
        }
        _ => {}
    }
}

/// Flattens a JSON value into `path.to.leaf: value` lines, one per scalar.
/// Arrays of scalars stay on a single line; arrays of objects (e.g. the sink
/// entries) are flattened with indexed paths.
fn flatten_config_value(
    value: &serde_json::Value,
    path: String,
    lines: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                lines.push(format!("{path}: {{}}"));
            }
            for (key, entry) in map {
                flatten_config_value(entry, format!("{path}.{key}"), lines);
            }
        }
        serde_json::Value::Array(items)
            if items.is_empty()
                || items.iter().all(|item| {
                    !matches!(
                        item,
                        serde_json::Value::Object(_)
                            | serde_json::Value::Array(_)
                    )
                }) =>
        {
            lines.push(format!("{path}: {value}"));
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                flatten_config_value(item, format!("{path}[{index}]"), lines);
            }
        }
        _ => lines.push(format!("{path}: {value}")),
    }
}

fn build_cors_layer(
    cors_config: &ave_bridge::CorsConfig,
) -> Result<Option<CorsLayer>, StartupError> {
    if !cors_config.enabled {
        return Ok(None);
    }

    let cors_layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            HeaderName::from_static("x-api-key"),
        ])
        .allow_credentials(cors_config.allow_credentials);

    if cors_config.allow_any_origin {
        warn!(
            target: TARGET,
            "CORS configured with allow_any_origin=true — security risk in production"
        );
        return Ok(Some(cors_layer.allow_origin(Any)));
    }

    if cors_config.allowed_origins.is_empty() {
        return Err(StartupError::CorsConfig(
            "CORS is enabled but neither 'allow_any_origin' nor 'allowed_origins' are configured"
                .to_string(),
        ));
    }

    let origins: Vec<HeaderValue> = cors_config
        .allowed_origins
        .iter()
        .map(|origin| {
            origin.parse::<HeaderValue>().map_err(|error| {
                StartupError::CorsConfig(format!(
                    "invalid allowed origin '{origin}': {error}"
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    Ok(Some(cors_layer.allow_origin(origins)))
}

pub async fn run() -> Result<(), StartupError> {
    let args = Args::parse();

    let mut config_path = args.config_path;
    if config_path.is_empty() {
        config_path = build_config_path();
    }

    let mut config = build_config(&config_path).map_err(|error| {
        StartupError::ConfigLoad {
            path: config_path.clone(),
            message: error.to_string(),
        }
    })?;
    config.node.safe_mode = if args.safe_mode {
        true
    } else if let Some(safe_mode) = build_safe_mode() {
        safe_mode
    } else {
        config.node.safe_mode
    };
    auth::request_meta::validate_proxy_config(&config.http.proxy)
        .map_err(StartupError::ProxyConfig)?;

    // Validate logging directory before init_logging so we can still
    // emit the error to stderr if the log directory is not writable.
    if let Err(e) = crate::directory_validation::validate_logging_path(&config)
    {
        eprintln!(
            "ERROR: cannot start logging — log directory is not accessible: {e}"
        );
        return Err(StartupError::DirectoryValidation(e));
    }

    let _log_handle = logging::init_logging(&config.logging).await;

    // Validate the remaining HTTP-managed paths after logging is ready
    // so permission errors appear in the application logs.
    if let Err(e) = crate::directory_validation::validate_http_paths(&config) {
        error!(target: TARGET, error = %e, "directory validation failed");
        return Err(StartupError::DirectoryValidation(e));
    }
    let secrets = StartupSecrets {
        auth_password: resolve_secret(args.auth_password, build_auth_password),
        key_password: resolve_secret(args.key_password, build_key_password),
        sink_password: resolve_secret(args.sink_password, build_sink_password),
        sink_api_key: resolve_secret(args.sink_api_key, build_sink_api_key),
    };

    log_effective_configuration(&config_path, &config, &secrets);

    let listener_http =
        tokio::net::TcpListener::bind(&config.http.http_address)
            .await
            .map_err(|error| StartupError::HttpBind {
                address: config.http.http_address.clone(),
                message: error.to_string(),
            })?;
    let cors = build_cors_layer(&config.http.cors)?;

    let auth_db: Option<Arc<AuthDatabase>> = auth::build_auth(
        &config.auth,
        &secrets.auth_password.value,
        config.node.spec.clone(),
    )
    .await
    .map_err(StartupError::AuthInit)?;

    let graceful_token = CancellationToken::new();
    let crash_token = CancellationToken::new();

    let (bridge, runners) = Bridge::build(
        &config,
        &secrets.key_password.value,
        Some(graceful_token.clone()),
        Some(crash_token.clone()),
    )
    .await
    .map_err(|error| {
        error!(target: TARGET, error = %error, "failed to build bridge");
        StartupError::BridgeBuild(error.to_string())
    })?;

    #[cfg(feature = "prometheus")]
    let registry = bridge.registry();
    #[cfg(feature = "prometheus")]
    if let Some(db) = auth_db.as_ref() {
        let mut registry_guard = registry.lock().await;
        db.register_prometheus_metrics(&mut registry_guard);
    }

    if let Some(https_address) = config.http.https_address.clone() {
        serve_https(HttpsServeArgs {
            config: &config,
            listener_http,
            cors,
            bridge,
            auth_db,
            runners,
            https_address,
            #[cfg(feature = "prometheus")]
            registry,
        })
        .await?;
    } else {
        serve_http(
            &config,
            listener_http,
            cors,
            bridge,
            auth_db,
            runners,
            #[cfg(feature = "prometheus")]
            registry,
        )
        .await?;
    }

    if crash_token.is_cancelled() {
        return Err(StartupError::FatalCrashSignal);
    }

    Ok(())
}

struct HttpsServeArgs<'a> {
    config: &'a BridgeConfig,
    listener_http: TcpListener,
    cors: Option<CorsLayer>,
    bridge: Bridge,
    auth_db: Option<Arc<AuthDatabase>>,
    runners: Vec<tokio::task::JoinHandle<()>>,
    https_address: String,
    #[cfg(feature = "prometheus")]
    registry: std::sync::Arc<
        tokio::sync::Mutex<prometheus_client::registry::Registry>,
    >,
}

async fn serve_https(args: HttpsServeArgs<'_>) -> Result<(), StartupError> {
    let HttpsServeArgs {
        config,
        listener_http,
        cors,
        bridge,
        auth_db,
        runners,
        https_address,
        #[cfg(feature = "prometheus")]
        registry,
    } = args;

    let https_socket =
        https_address.parse::<SocketAddr>().map_err(|error| {
            StartupError::HttpsAddress {
                address: https_address.clone(),
                message: error.to_string(),
            }
        })?;

    tokio::spawn(async move {
        if let Err(error) =
            redirect_http_to_https(https_socket.port(), listener_http).await
        {
            error!(
                target: TARGET,
                error = %error,
                "http to https redirect server stopped"
            );
        }
    });

    let cert_path = config
        .http
        .https_cert_path
        .clone()
        .ok_or(StartupError::MissingHttpsCertPath)?;
    let key_path = config
        .http
        .https_private_key_path
        .clone()
        .ok_or(StartupError::MissingHttpsKeyPath)?;

    let self_signed_config = config.http.self_signed_cert.clone();

    if self_signed_config.enabled
        && cert_needs_renewal(&self_signed_config, &cert_path, &key_path).await
    {
        generate_self_signed_cert(&self_signed_config, &cert_path, &key_path)
            .await
            .map_err(|e| StartupError::SelfSignedCert(e.to_string()))?;
    }

    let tls = RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .map_err(|error| StartupError::TlsConfig(error.to_string()))?;

    if self_signed_config.enabled {
        let tls_clone = tls.clone();
        let paths = CertPaths {
            cert_path,
            key_path,
        };
        tokio::spawn(cert_renewal_task(self_signed_config, paths, tls_clone));
    }

    let handle = Handle::new();
    let handle_clone = handle.clone();
    tokio::spawn(async move {
        join_all(runners).await;
        handle.graceful_shutdown(Some(Duration::from_secs(10)));
        info!(target: TARGET, "all runners stopped");
    });

    let app = tower_trace(build_routes(
        config.http.enable_doc,
        config.http.proxy.clone(),
        bridge,
        auth_db,
        #[cfg(feature = "prometheus")]
        registry,
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    ));
    let app = if let Some(cors_layer) = cors {
        app.layer(cors_layer)
    } else {
        app
    };

    axum_server::bind_rustls(https_socket, tls)
        .handle(handle_clone)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|error| StartupError::HttpsServer(error.to_string()))?;

    Ok(())
}

async fn serve_http(
    config: &BridgeConfig,
    listener_http: TcpListener,
    cors: Option<CorsLayer>,
    bridge: Bridge,
    auth_db: Option<Arc<AuthDatabase>>,
    runners: Vec<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "prometheus")] registry: std::sync::Arc<
        tokio::sync::Mutex<prometheus_client::registry::Registry>,
    >,
) -> Result<(), StartupError> {
    let app = tower_trace(build_routes(
        config.http.enable_doc,
        config.http.proxy.clone(),
        bridge,
        auth_db,
        #[cfg(feature = "prometheus")]
        registry,
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    ));
    let app = if let Some(cors_layer) = cors {
        app.layer(cors_layer)
    } else {
        app
    };

    axum::serve(
        listener_http,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        join_all(runners).await;
        info!(target: TARGET, "all runners stopped");
    })
    .await
    .map_err(|error| StartupError::HttpServer(error.to_string()))?;

    Ok(())
}

async fn redirect_http_to_https(
    https: u16,
    listener_http: TcpListener,
) -> Result<(), StartupError> {
    fn make_https(
        host: String,
        uri: Uri,
        ports: Ports,
    ) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();
        parts.scheme = Some(Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse()?);
        }

        let auth: Authority = host.parse()?;

        let http_port: u16 = ports.http.parse()?;
        let https_port: u16 = ports.https.parse()?;

        let new_auth_str = match auth.port() {
            Some(p) if p == http_port => {
                format!("{}:{}", auth.host(), https_port)
            }
            Some(_) => auth.as_str().to_string(),
            None => {
                if https_port == 443 {
                    auth.host().to_string()
                } else {
                    format!("{}:{}", auth.host(), https_port)
                }
            }
        };

        parts.authority = Some(new_auth_str.parse()?);
        Ok(Uri::from_parts(parts)?)
    }

    let ports = Ports {
        https: https.to_string(),
        http: listener_http
            .local_addr()
            .map_err(|error| StartupError::Listener(error.to_string()))?
            .port()
            .to_string(),
    };

    let app =
        Router::new().fallback(any(move |headers: HeaderMap, uri: Uri| {
            let ports = ports.clone();
            async move {
                let host = headers
                    .get(header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                match make_https(host, uri, ports) {
                    Ok(uri) => {
                        Redirect::permanent(&uri.to_string()).into_response()
                    }
                    Err(error) => (
                        StatusCode::BAD_REQUEST,
                        format!("invalid redirect target: {error}"),
                    )
                        .into_response(),
                }
            }
        }));
    axum::serve(listener_http, app)
        .await
        .map_err(|error| StartupError::RedirectServer(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_bridge::ave_common::sink::SinkAuthConfig;
    use ave_bridge::{
        HttpSinkConfig, KafkaSinkConfig, SinkConfigEntry, SinkServer,
        SinkTarget, SinkTransportConfig,
    };

    /// Config exercising the dump: both sink transports, nested targets and
    /// secrets that must be redacted.
    fn test_config() -> BridgeConfig {
        let mut config = BridgeConfig::default();
        config.auth.superadmin = "superadmin-secret-name".to_string();
        config.sinks = vec![
            SinkConfigEntry {
                target: SinkTarget::Schema {
                    schema_id: "governance".to_string(),
                    governance_id: None,
                },
                servers: vec![SinkServer {
                    server: "http-sink".to_string(),
                    transport: SinkTransportConfig::Http(Box::new(HttpSinkConfig {
                        url: "https://sink.example.com".to_string(),
                        auth: Some(SinkAuthConfig {
                            auth_url: String::new(),
                            username: String::new(),
                            api_key: "top-secret-key".to_string(),
                        }),
                        ..HttpSinkConfig::default()
                    })),
                    ..SinkServer::default()
                }],
            },
            SinkConfigEntry {
                target: SinkTarget::Schema {
                    schema_id: "Example".to_string(),
                    governance_id: Some("gov-1".to_string()),
                },
                servers: vec![SinkServer {
                    server: "kafka-sink".to_string(),
                    transport: SinkTransportConfig::Kafka(KafkaSinkConfig {
                        bootstrap_servers: "broker:9092".to_string(),
                        topic: "ave".to_string(),
                        ..KafkaSinkConfig::default()
                    }),
                    ..SinkServer::default()
                }],
            },
        ];
        config
    }

    /// Independent leaf walk used by the completeness check: computes the
    /// `path: value` lines the dump must contain, straight from the
    /// serialized configuration.
    fn expected_leaves(
        value: &serde_json::Value,
        path: String,
        lines: &mut Vec<String>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                if map.is_empty() {
                    lines.push(format!("{path}: {{}}"));
                }
                for (key, entry) in map {
                    expected_leaves(entry, format!("{path}.{key}"), lines);
                }
            }
            serde_json::Value::Array(items)
                if items.is_empty()
                    || items.iter().all(|item| {
                        !matches!(
                            item,
                            serde_json::Value::Object(_)
                                | serde_json::Value::Array(_)
                        )
                    }) =>
            {
                lines.push(format!("{path}: {value}"));
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    expected_leaves(item, format!("{path}[{index}]"), lines);
                }
            }
            _ => lines.push(format!("{path}: {value}")),
        }
    }

    /// Assert that `lines` contains `expected`. On failure, print the whole
    /// dump so the missing parameter is visible.
    fn assert_dump_line(lines: &[&String], expected: &str) {
        if !lines.iter().any(|line| line.as_str() == expected) {
            let dump = lines
                .iter()
                .map(|line| format!("  {line}"))
                .collect::<Vec<_>>()
                .join("\n");
            panic!("missing config line: {expected}\nfull dump:\n{dump}");
        }
    }

    /// Critical dump paths that must always be present. This list breaks the
    /// completeness tautology: if a new field is added but the dump or the
    /// redaction misses it, the test fails even though the serialized config
    /// contains it.
    const CRITICAL_DUMP_PATHS: &[&str] = &[
        "auth.superadmin: \"***\"",
        "sinks[0].servers[0].transport.url: \"https://sink.example.com\"",
        "sinks[0].servers[0].transport.auth.api_key: \"***\"",
        "sinks[0].servers[0].transport.retry_base_delay_ms: 500",
        "sinks[0].servers[0].transport.health_check_url: null",
        "sinks[0].servers[0].transport.token_refresh_margin_secs: 30",
        "sinks[1].servers[0].transport.bootstrap_servers: \"broker:9092\"",
    ];

    /// Every configuration parameter must appear in the startup dump, and no
    /// secret value may leak into it.
    #[test]
    fn config_dump_covers_every_parameter_and_redacts_secrets() {
        let config = test_config();
        let sections = config_log_sections(&config).unwrap();

        // Every top-level config key is logged as a section.
        let raw = serde_json::to_value(&config).unwrap();
        let raw_map = raw.as_object().unwrap();
        assert_eq!(sections.len(), raw_map.len());
        for key in raw_map.keys() {
            assert!(
                sections.iter().any(|(section, _)| section == key),
                "missing section [{key}]"
            );
        }

        // Every parameter leaf appears in the dump (redacted when sensitive).
        let mut expected = Vec::new();
        for (key, value) in raw_map {
            expected_leaves(value, key.clone(), &mut expected);
        }
        let lines: Vec<&String> = sections
            .iter()
            .flat_map(|(_, lines)| lines.iter())
            .collect();
        for leaf in &expected {
            let sensitive = REDACTED_CONFIG_KEYS.iter().any(|key| {
                leaf.contains(&format!(".{key}: ")) && !leaf.ends_with(": \"\"")
            });
            let expected_line = if sensitive {
                let (path, _) = leaf.rsplit_once(": ").unwrap();
                format!("{path}: \"***\"")
            } else {
                leaf.clone()
            };
            assert_dump_line(&lines, &expected_line);
        }

        // Critical parameters must be present, regardless of the serialized
        // shape of the config.
        for path in CRITICAL_DUMP_PATHS {
            assert_dump_line(&lines, path);
        }

        // No secret value leaks into the dump.
        for line in &lines {
            assert!(
                !line.contains("superadmin-secret-name"),
                "superadmin leaks in: {line}"
            );
            assert!(
                !line.contains("top-secret-key"),
                "sink api_key leaks in: {line}"
            );
        }

        // Any leaf key whose final segment looks like a secret must be
        // redacted (either by REDACTED_CONFIG_KEYS or by a custom Serialize
        // such as `SinkAuthConfig.api_key`). Checking only the last segment
        // avoids false positives on non-secret fields like `api_key.prefix`.
        let secret_words =
            ["password", "secret", "token", "api_key", "credential"];
        for line in &lines {
            let Some((path, value)) = line.rsplit_once(": ") else {
                continue;
            };
            let is_string_value = value.starts_with('"')
                && value.ends_with('"')
                && value.len() >= 2;
            if !is_string_value {
                continue;
            }
            let is_redacted = value == "\"***\"";
            let is_empty = value == "\"\"";
            if is_redacted || is_empty {
                continue;
            }
            let last_segment = path.rsplit('.').next().unwrap_or(path);
            let segment_lower = last_segment.to_lowercase();
            assert!(
                !secret_words.iter().any(|word| segment_lower.contains(word)),
                "config key '{path}' looks like a secret but is not redacted in the dump"
            );
        }
    }
}
