use std::{net::SocketAddr, time::Duration};

use auth::AuthDatabase;
use ave_bridge::{
    Bridge,
    clap::Parser,
    config::Config as BridgeConfig,
    settings::{
        build_config,
        command::{
            Args, build_auth_password, build_config_path, build_key_password,
            build_sink_api_key, build_sink_password,
        },
    },
};
use axum::{
    BoxError,
    handler::HandlerWithoutStateExt,
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header,
        uri::{Authority, Scheme},
    },
    response::Redirect,
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use futures::future::join_all;
use middleware::tower_trace;
use server::build_routes;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
};
use tracing::{error, info, warn};

use crate::auth::build_auth;
use crate::self_signed_cert::{
    CertPaths, cert_needs_renewal, cert_renewal_task, generate_self_signed_cert,
};

mod auth;
mod config_types;
mod doc;
mod error;
mod logging;
mod middleware;
mod self_signed_cert;
mod server;

#[cfg(all(feature = "sqlite", feature = "rocksdb"))]
compile_error!("Select only one: 'sqlite' or 'rocksdb'");

#[cfg(not(any(feature = "sqlite", feature = "rocksdb")))]
compile_error!("You must enable 'sqlite' or 'rocksdb'");

#[cfg(not(feature = "ext-sqlite"))]
compile_error!("You must enable 'ext-sqlite'");

#[derive(Clone)]
struct Ports {
    http: String,
    https: String,
}

const TARGET: &str = "ave::http";

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

    info!(target: TARGET, "[http]");
    info!(target: TARGET, "  address   : {}", config.http.http_address);
    if let Some(ref https) = config.http.https_address {
        info!(target: TARGET, "  https     : {}", https);
        if let Some(ref cert) = config.http.https_cert_path {
            info!(target: TARGET, "  cert      : {}", cert.display());
        }
        if let Some(ref key) = config.http.https_private_key_path {
            info!(target: TARGET, "  cert key  : {}", key.display());
        }
    } else {
        info!(target: TARGET, "  https     : disabled");
    }
    if config.http.self_signed_cert.enabled {
        info!(
            target: TARGET,
            "  self-signed: enabled (cn: {})",
            config.http.self_signed_cert.common_name
        );
        info!(
            target: TARGET,
            "  self-signed san: {}",
            config.http.self_signed_cert.san.join(", ")
        );
        info!(
            target: TARGET,
            "  self-signed ttl: {}d | renew before: {}d | check: {}s",
            config.http.self_signed_cert.validity_days,
            config.http.self_signed_cert.renew_before_days,
            config.http.self_signed_cert.check_interval_secs
        );
    } else {
        info!(target: TARGET, "  self-signed: disabled");
    }
    info!(target: TARGET, "  docs      : {}", config.http.enable_doc);
    if config.http.cors.enabled {
        if config.http.cors.allow_any_origin {
            info!(
                target: TARGET,
                "  cors      : enabled (any origin - WARNING)"
            );
        } else {
            info!(
                target: TARGET,
                "  cors      : enabled ({} origins)",
                config.http.cors.allowed_origins.len()
            );
            for origin in &config.http.cors.allowed_origins {
                info!(target: TARGET, "  cors orig : {}", origin);
            }
        }
        info!(
            target: TARGET,
            "  cors creds: {}",
            config.http.cors.allow_credentials
        );
    } else {
        info!(target: TARGET, "  cors      : disabled");
    }

    info!(target: TARGET, "[network]");
    info!(target: TARGET, "  type      : {}", config.node.network.node_type);
    if config.node.network.listen_addresses.is_empty() {
        info!(target: TARGET, "  listen    : none");
    } else {
        for addr in &config.node.network.listen_addresses {
            info!(target: TARGET, "  listen    : {}", addr);
        }
    }
    if config.node.network.external_addresses.is_empty() {
        info!(target: TARGET, "  external  : none");
    } else {
        for addr in &config.node.network.external_addresses {
            info!(target: TARGET, "  external  : {}", addr);
        }
    }
    if config.node.network.boot_nodes.is_empty() {
        info!(target: TARGET, "  boot nodes: 0");
    } else {
        info!(
            target: TARGET,
            "  boot nodes: {}",
            config.node.network.boot_nodes.len()
        );
        for boot in &config.node.network.boot_nodes {
            info!(
                target: TARGET,
                "  boot node : {} ({} addr)",
                boot.peer_id,
                boot.address.len()
            );
            for addr in &boot.address {
                info!(target: TARGET, "    addr    : {}", addr);
            }
        }
    }
    info!(
        target: TARGET,
        "  mem limits: {}",
        config.node.network.memory_limits
    );
    info!(
        target: TARGET,
        "  dht walk  : {}",
        config.node.network.routing.get_dht_random_walk()
    );
    info!(
        target: TARGET,
        "  discover< : {}",
        config.node.network.routing.get_discovery_limit()
    );
    info!(
        target: TARGET,
        "  dht private: {}",
        config.node.network.routing.get_allow_private_address_in_dht()
    );
    info!(
        target: TARGET,
        "  dht dns   : {}",
        config.node.network.routing.get_allow_dns_address_in_dht()
    );
    info!(
        target: TARGET,
        "  dht loopbk: {}",
        config.node.network.routing.get_allow_loop_back_address_in_dht()
    );
    info!(
        target: TARGET,
        "  dht disjnt: {}",
        config
            .node
            .network
            .routing
            .get_kademlia_disjoint_query_paths()
    );
    let control = &config.node.network.control_list;
    let allow_list = control.get_allow_list();
    let block_list = control.get_block_list();
    let allow_services = control.get_service_allow_list();
    let block_services = control.get_service_block_list();
    info!(
        target: TARGET,
        "  control-list enabled: {}",
        control.get_enable()
    );
    info!(
        target: TARGET,
        "  control-list interval: {}s",
        control.get_interval_request().as_secs()
    );
    info!(
        target: TARGET,
        "  control-list timeout : {}s",
        control.get_request_timeout().as_secs()
    );
    info!(
        target: TARGET,
        "  control-list concurr : {}",
        control.get_max_concurrent_requests()
    );
    info!(
        target: TARGET,
        "  control-list allow peers: {}",
        allow_list.len()
    );
    info!(
        target: TARGET,
        "  control-list blocked peers: {}",
        block_list.len()
    );
    info!(
        target: TARGET,
        "  control-list allow services: {}",
        allow_services.len()
    );
    info!(
        target: TARGET,
        "  control-list block services: {}",
        block_services.len()
    );
    for peer in &allow_list {
        info!(target: TARGET, "    allow peer: {}", peer);
    }
    for peer in &block_list {
        info!(target: TARGET, "    blocked peer: {}", peer);
    }
    for service in &allow_services {
        info!(target: TARGET, "    allow service: {}", service);
    }
    for service in &block_services {
        info!(target: TARGET, "    block service: {}", service);
    }
    info!(
        target: TARGET,
        "  msg limit : {} bytes",
        config.node.network.max_app_message_bytes
    );
    info!(
        target: TARGET,
        "  out limit : {} bytes/peer",
        config.node.network.max_pending_outbound_bytes_per_peer
    );
    info!(
        target: TARGET,
        "  in limit  : {} bytes/peer",
        config.node.network.max_pending_inbound_bytes_per_peer
    );
    info!(
        target: TARGET,
        "  out total : {} bytes (0=unlimited)",
        config.node.network.max_pending_outbound_bytes_total
    );
    info!(
        target: TARGET,
        "  in total  : {} bytes (0=unlimited)",
        config.node.network.max_pending_inbound_bytes_total
    );

    info!(target: TARGET, "[node]");
    info!(target: TARGET, "  keys      : {}", config.keys_path.display());
    info!(target: TARGET, "  db        : {:?}", config.node.internal_db.db);
    info!(
        target: TARGET,
        "  db durable: {}",
        config.node.internal_db.durability
    );
    info!(target: TARGET, "  ext db    : {:?}", config.node.external_db.db);
    info!(
        target: TARGET,
        "  ext durable: {}",
        config.node.external_db.durability
    );
    info!(
        target: TARGET,
        "  keypair   : {:?}",
        config.node.keypair_algorithm
    );
    info!(target: TARGET, "  hash      : {:?}", config.node.hash_algorithm);
    info!(
        target: TARGET,
        "  contracts : {}",
        config.node.contracts_path.display()
    );
    info!(target: TARGET, "  tracking  : {}", config.node.tracking_size);
    match &config.node.spec {
        Some(spec) => info!(target: TARGET, "  wasm spec : {:?}", spec),
        None => info!(target: TARGET, "  wasm spec : auto"),
    }
    info!(target: TARGET, "  always acc: {}", config.node.always_accept);
    info!(target: TARGET, "  service   : {}", config.node.is_service);

    info!(target: TARGET, "[auth]");
    info!(target: TARGET, "  enabled   : {}", config.auth.enable);
    info!(
        target: TARGET,
        "  database  : {}",
        config.auth.database_path.display()
    );
    info!(target: TARGET, "  durability: {}", config.auth.durability);
    let has_superadmin = !config.auth.superadmin.trim().is_empty();
    info!(
        target: TARGET,
        "  superadmin: {}",
        if has_superadmin {
            "configured (redacted)"
        } else {
            "not configured"
        }
    );
    info!(
        target: TARGET,
        "  key ttl   : {}s | max {} per user",
        config.auth.api_key.default_ttl_seconds,
        config.auth.api_key.max_keys_per_user
    );
    info!(
        target: TARGET,
        "  lockout   : {} attempts -> {}s",
        config.auth.lockout.max_attempts,
        config.auth.lockout.duration_seconds
    );
    if config.auth.rate_limit.enable {
        info!(
            target: TARGET,
            "  ratelimit : {} req / {}s window",
            config.auth.rate_limit.max_requests,
            config.auth.rate_limit.window_seconds
        );
        info!(
            target: TARGET,
            "  rl by key : {} | by ip: {} | cleanup: {}s",
            config.auth.rate_limit.limit_by_key,
            config.auth.rate_limit.limit_by_ip,
            config.auth.rate_limit.cleanup_interval_seconds
        );
        info!(
            target: TARGET,
            "  rl sensitv: {} endpoint(s)",
            config.auth.rate_limit.sensitive_endpoints.len()
        );
        for endpoint in &config.auth.rate_limit.sensitive_endpoints {
            match endpoint.window_seconds {
                Some(window) => info!(
                    target: TARGET,
                    "    - {} => {} req / {}s",
                    endpoint.endpoint,
                    endpoint.max_requests,
                    window
                ),
                None => info!(
                    target: TARGET,
                    "    - {} => {} req / default window",
                    endpoint.endpoint,
                    endpoint.max_requests
                ),
            }
        }
    } else {
        info!(target: TARGET, "  ratelimit : disabled");
    }
    info!(
        target: TARGET,
        "  session   : audit={} retention={}d max={}",
        config.auth.session.audit_enable,
        config.auth.session.audit_retention_days,
        config.auth.session.audit_max_entries
    );

    info!(target: TARGET, "[logging]");
    info!(target: TARGET, "  level     : {}", config.logging.level);
    info!(target: TARGET, "  stdout    : {}", config.logging.output.stdout);
    info!(target: TARGET, "  file      : {}", config.logging.output.file);
    info!(target: TARGET, "  api       : {}", config.logging.output.api);
    if config.logging.output.file {
        info!(
            target: TARGET,
            "  file path : {}",
            config.logging.file_path.display()
        );
        info!(
            target: TARGET,
            "  rotation  : {} | max size: {} | max files: {}",
            config.logging.rotation,
            config.logging.max_size,
            config.logging.max_files
        );
    }
    if config.logging.output.api {
        match &config.logging.api_url {
            Some(api_url) => info!(target: TARGET, "  api url   : {}", api_url),
            None => info!(target: TARGET, "  api url   : missing"),
        }
    }

    info!(target: TARGET, "[sink]");
    if config.sink.auth.is_empty() {
        info!(target: TARGET, "  auth url  : none");
    } else {
        info!(target: TARGET, "  auth url  : {}", config.sink.auth);
    }
    if config.sink.username.is_empty() {
        info!(target: TARGET, "  username  : none");
    } else {
        info!(target: TARGET, "  username  : {}", config.sink.username);
    }
    info!(target: TARGET, "  schemas   : {}", config.sink.sinks.len());
    for (schema, servers) in &config.sink.sinks {
        info!(
            target: TARGET,
            "  schema '{}': {} server(s)",
            schema,
            servers.len()
        );
        for s in servers {
            info!(
                target: TARGET,
                "    - {} | {} | auth: {} | events: {:?}",
                s.server,
                s.url,
                s.auth,
                s.events
            );
        }
    }

    info!(target: TARGET, "--- end ---");
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut config_path = args.config_path;
    if config_path.is_empty() {
        config_path = build_config_path();
    }

    let config = build_config(&config_path).unwrap_or_else(|e| {
        eprintln!("Can not build config: {e}");
        panic!("Can not build config");
    });

    let _log_handle = logging::init_logging(&config.logging).await;
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
            .expect("Can not build TCP listener with http address");

    // Build CORS layer based on configuration
    let cors_config = &config.http.cors;
    let cors = if cors_config.enabled {
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

        // Configure origins based on configuration
        if cors_config.allow_any_origin {
            // SECURITY WARNING: This allows ANY website to make requests (CVSS 6.5)
            // Only use in development or if API is not accessed from browsers
            warn!(
                target: TARGET,
                "CORS configured with allow_any_origin=true — security risk in production"
            );
            cors_layer.allow_origin(Any)
        } else if !cors_config.allowed_origins.is_empty() {
            // Parse allowed origins from configuration
            let origins: Vec<HeaderValue> = cors_config
                .allowed_origins
                .iter()
                .filter_map(|origin| {
                    origin
                        .parse::<HeaderValue>()
                        .inspect_err(|e| {
                            error!(
                                target: TARGET,
                                origin = %origin,
                                error = %e,
                                "invalid CORS origin"
                            );
                        })
                        .ok()
                })
                .collect();

            if origins.is_empty() {
                // All origins failed to parse - this is a configuration error
                panic!(
                    "CORS enabled with allowed_origins but all origins are invalid. \
                    Please check your CORS configuration in config.json. \
                    Provided origins: {:?}",
                    cors_config.allowed_origins
                );
            }

            cors_layer.allow_origin(origins)
        } else {
            // CORS enabled but no origins configured and allow_any_origin is false
            // This is a misconfiguration - fail fast
            panic!(
                "CORS is enabled but no valid configuration provided. \
                Either set 'allow_any_origin: true' (development only) or \
                provide 'allowed_origins' list in config.json"
            );
        }
    } else {
        // CORS disabled, use permissive layer
        CorsLayer::permissive()
    };

    // SECURITY FIX: Add security headers to prevent API key leakage
    // Referrer-Policy: no-referrer prevents API keys from leaking via Referer header
    // This is critical when API keys are in headers, as browser may leak them
    let security_headers = ServiceBuilder::new()
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

    let auth_db: Option<Arc<AuthDatabase>> = build_auth(
        &config.auth,
        &secrets.auth_password.value,
        config.node.spec.clone(),
    )
    .await;

    let (bridge, runners) = Bridge::build(
        &config,
        &secrets.key_password.value,
        &secrets.sink_password.value,
        &secrets.sink_api_key.value,
        None,
    )
    .await
    .map_err(|e| {
        error!(target: TARGET, error = %e, "failed to build bridge");
    })
    .expect("Can not build Bridge");

    #[cfg(feature = "prometheus")]
    let registry = bridge.registry();

    if let Some(https_address) = config.http.https_address {
        let https_address = https_address
            .parse::<SocketAddr>()
            .expect("Can not parse Https address as SocketAddr");

        tokio::spawn(redirect_http_to_https(
            https_address.port(),
            listener_http,
        ));
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Can not install ring for RustTLS");

        // Certificate paths are validated in build_config, unwrap is safe here
        let cert_path = config.http.https_cert_path.expect(
            "https_cert_path required for HTTPS (validated in build_config)",
        );
        let key_path = config
            .http
            .https_private_key_path
            .expect("https_private_key_path required for HTTPS (validated in build_config)");

        let self_signed_config = config.http.self_signed_cert.clone();

        // If self-signed mode is enabled, generate certificate if needed
        if self_signed_config.enabled {
            info!(
                target: TARGET,
                "Self-signed certificate mode enabled"
            );

            if cert_needs_renewal(&self_signed_config, &cert_path, &key_path)
                .await
            {
                match generate_self_signed_cert(
                    &self_signed_config,
                    &cert_path,
                    &key_path,
                )
                .await
                {
                    Ok(()) => {
                        info!(
                            target: TARGET,
                            path = %cert_path.display(),
                            "self-signed certificate generated"
                        );
                    }
                    Err(e) => {
                        error!(
                            target: TARGET,
                            error = %e,
                            "failed to generate self-signed certificate"
                        );
                        return;
                    }
                }
            }
        }

        let tls = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("Can not build tls");

        // Start certificate renewal background task if self-signed mode is enabled
        if self_signed_config.enabled {
            let tls_clone = tls.clone();
            let paths = CertPaths {
                cert_path,
                key_path,
            };
            tokio::spawn(cert_renewal_task(
                self_signed_config,
                paths,
                tls_clone,
            ));
        }

        let handle = Handle::new();

        let handle_clone = handle.clone();
        tokio::spawn(async move {
            join_all(runners).await;
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
            info!(target: TARGET, "all runners stopped");
        });

        axum_server::bind_rustls(https_address, tls)
            .handle(handle_clone)
            .serve(
                tower_trace(build_routes(
                    config.http.enable_doc,
                    bridge,
                    auth_db,
                    #[cfg(feature = "prometheus")]
                    registry,
                ))
                .layer(security_headers.clone())
                .layer(cors)
                .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("Can not run axum server");
    } else {
        axum::serve(
            listener_http,
            tower_trace(build_routes(
                config.http.enable_doc,
                bridge,
                auth_db,
                #[cfg(feature = "prometheus")]
                registry,
            ))
            .layer(security_headers)
            .layer(cors)
            .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            join_all(runners).await;
            info!(target: TARGET, "all runners stopped");
        })
        .await
        .expect("Can not run axum server");
    }
}

async fn redirect_http_to_https(https: u16, listener_http: TcpListener) {
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
            Some(_) => auth.as_str().to_string(), // puerto “no esperado”: no lo tocamos
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
            .expect("Invalid listener http")
            .port()
            .to_string(),
    };

    let redirect = move |headers: HeaderMap, uri: Uri| async move {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        match make_https(host, uri, ports) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    axum::serve(listener_http, redirect.into_make_service())
        .await
        .expect("Can not run axum server, redirect http to https");
}
