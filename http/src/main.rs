use std::{net::SocketAddr, time::Duration};

use auth::AuthDatabase;
use ave_bridge::{
    Bridge,
    clap::Parser,
    settings::{
        build_config,
        command::{
            Args, build_config_path, build_key_password, build_sink_api_key,
            build_sink_password,
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

    // Log effective configuration so misconfiguration is visible at startup
    info!(target: TARGET, "--- configuration ---");

    info!(target: TARGET, "[http]");
    info!(target: TARGET, "  address   : {}", config.http.http_address);
    if let Some(ref https) = config.http.https_address {
        info!(target: TARGET, "  https     : {}", https);
        if let Some(ref cert) = config.http.https_cert_path {
            info!(target: TARGET, "  cert      : {}", cert.display());
        }
        if config.http.self_signed_cert.enabled {
            info!(target: TARGET, "  self-signed: enabled ({})", config.http.self_signed_cert.common_name);
        }
    } else {
        info!(target: TARGET, "  https     : disabled");
    }
    info!(target: TARGET, "  docs      : {}", config.http.enable_doc);
    if config.http.cors.enabled {
        if config.http.cors.allow_any_origin {
            info!(target: TARGET, "  cors      : enabled (any origin - WARNING)");
        } else {
            info!(target: TARGET, "  cors      : enabled ({} origins)", config.http.cors.allowed_origins.len());
        }
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
    for addr in &config.node.network.external_addresses {
        info!(target: TARGET, "  external  : {}", addr);
    }
    info!(target: TARGET, "  boot nodes: {}", config.node.network.boot_nodes.len());
    info!(target: TARGET, "  mem limits: {}", config.node.network.memory_limits);

    info!(target: TARGET, "[node]");
    info!(target: TARGET, "  keys      : {}", config.keys_path.display());
    info!(target: TARGET, "  db        : {:?}", config.node.internal_db.db);
    info!(target: TARGET, "  keypair   : {:?}", config.node.keypair_algorithm);
    info!(target: TARGET, "  always acc: {}", config.node.always_accept);
    info!(target: TARGET, "  service   : {}", config.node.is_service);

    info!(target: TARGET, "[auth]");
    info!(target: TARGET, "  enabled   : {}", config.auth.enable);
    if config.auth.enable {
        info!(target: TARGET, "  database  : {}", config.auth.database_path.display());
        info!(target: TARGET, "  superadmin: {}", config.auth.superadmin);
        info!(target: TARGET, "  key ttl   : {}s | max {} per user", config.auth.api_key.default_ttl_seconds, config.auth.api_key.max_keys_per_user);
        info!(target: TARGET, "  lockout   : {} attempts -> {}s", config.auth.lockout.max_attempts, config.auth.lockout.duration_seconds);
        if config.auth.rate_limit.enable {
            info!(target: TARGET, "  ratelimit : {} req / {}s window", config.auth.rate_limit.max_requests, config.auth.rate_limit.window_seconds);
        } else {
            info!(target: TARGET, "  ratelimit : disabled");
        }
    }

    info!(target: TARGET, "[logging]");
    info!(target: TARGET, "  level     : {}", config.logging.level);
    info!(target: TARGET, "  stdout    : {}", config.logging.output.stdout);
    if config.logging.output.file {
        info!(target: TARGET, "  file      : {} | rotation: {} | max files: {}", config.logging.file_path.display(), config.logging.rotation, config.logging.max_files);
    }

    if !config.sink.sinks.is_empty() {
        info!(target: TARGET, "[sink]");
        for (schema, servers) in &config.sink.sinks {
            info!(target: TARGET, "  schema '{}': {} server(s)", schema, servers.len());
            for s in servers {
                info!(target: TARGET, "    - {} (auth: {})", s.url, s.auth);
            }
        }
    }

    info!(target: TARGET, "--- end ---");

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

    let auth_db: Option<Arc<AuthDatabase>> =
        build_auth(&config.auth, &args.auth_password, config.node.spec.clone()).await;

    let mut key_password = args.key_password;
    if key_password.is_empty() {
        key_password = build_key_password();
    }

    let mut sink_password = args.sink_password;
    if sink_password.is_empty() {
        sink_password = build_sink_password();
    }

    let mut sink_api_key = args.sink_api_key;
    if sink_api_key.is_empty() {
        sink_api_key = build_sink_api_key();
    }

    let (bridge, runners) = Bridge::build(
        &config,
        &key_password,
        &sink_password,
        &sink_api_key,
        None,
    )
    .await
    .map_err(|e| {
        error!(target: TARGET, error = %e, "failed to build bridge");
    })
    .expect("Can not build Bridge");

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
            tower_trace(build_routes(config.http.enable_doc, bridge, auth_db))
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
