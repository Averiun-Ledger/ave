use std::{net::SocketAddr, path::PathBuf, time::Duration};

use auth::{
    AuthConfig, AuthDatabase,
    integration::{cleanup_old_data, initialize_auth_database, log_auth_statistics},
};
use ave_bridge::{
    Bridge,
    clap::Parser,
    settings::{
        build_config, build_config_path, build_password, build_sink_password,
        command::Args,
    },
};
use axum::{
    BoxError,
    handler::HandlerWithoutStateExt,
    http::{
        HeaderName, Method, StatusCode, Uri, header,
        uri::{Authority, Scheme},
    },
    response::Redirect,
};
use axum_extra::extract::Host;
use axum_server::{Handle, tls_rustls::RustlsConfig};
use enviroment::{
    build_address_http, build_address_https, build_https_cert,
    build_https_private_key,
};
use futures::future::join_all;
use middleware::tower_trace;
use serde::Deserialize;
use server::build_routes;
use std::sync::Arc;
use tokio::{net::TcpListener, time::interval};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

use crate::enviroment::build_auth_config;

mod auth;
mod config_types;
mod doc;
mod enviroment;
mod error;
mod logging;
mod middleware;
mod server;

#[cfg(all(feature = "sqlite", feature = "rocksdb"))]
compile_error!("Select only one: 'sqlite' or 'rocksdb'.");

#[cfg(not(any(feature = "sqlite", feature = "rocksdb")))]
compile_error!("You must enable 'sqlite' or 'rocksdb'.");

#[cfg(not(feature = "ext-sqlite"))]
compile_error!("You must enable 'ext-sqlite'.");

#[derive(Clone)]
struct Ports {
    http: String,
    https: String,
}

const TARGET_HTTP: &str = "AveHttp";

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut password = args.password;
    if password.is_empty() {
        password = build_password();
    }

    let mut password_sink = args.password_sink;
    if password_sink.is_empty() {
        password_sink = build_sink_password();
    }

    let mut config_path = args.config_path;
    if config_path.is_empty() {
        config_path = build_config_path();
    }

    let mut auth_config_path = args.auth_config_path;
    if auth_config_path.is_empty() {
        auth_config_path = build_auth_config();
    }

    let https_address = build_address_https();

    let listener_http = tokio::net::TcpListener::bind(build_address_http())
        .await
        .unwrap();

    let cors = CorsLayer::new()
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
        .allow_origin(Any);

    let bridge_config = build_config(args.env_config, &config_path).unwrap();
    let _log_handle = logging::init_logging(&bridge_config.logging).await;
    
    // Load authentication configuration (optional)
    let auth_config = load_auth_config(auth_config_path);

    // Initialize authentication database (optional)
    let auth_db: Option<Arc<AuthDatabase>> = match auth_config {
        Some(auth_config) if auth_config.enabled => {
            match initialize_auth_database(&auth_config).await {
                Ok(db) => {
                    info!(TARGET_HTTP, "Authentication system ENABLED");
                    log_auth_statistics(&db).await;
                    // Background maintenance: cleanup audit logs, rate limits, expired API keys
                    let maintenance_db = db.clone();
                    tokio::spawn(async move {
                        let mut ticker = interval(Duration::from_secs(3600));
                        loop {
                            ticker.tick().await;
                            if let Err(e) = cleanup_old_data(&maintenance_db).await {
                                warn!(TARGET_HTTP, "Maintenance task failed: {}", e);
                            }
                        }
                    });
                    Some(db)
                }
                Err(e) => {
                    error!(
                        TARGET_HTTP,
                        "Failed to initialize auth system: {}", e
                    );
                    warn!(TARGET_HTTP, "Continuing WITHOUT authentication");
                    None
                }
            }
        }
        Some(_) => {
            info!(TARGET_HTTP, "Authentication explicitly DISABLED");
            None
        }
        None => {
            info!(
                TARGET_HTTP,
                "No authentication configuration found - starting without auth"
            );
            None
        }
    };

    let (bridge, runners) =
        Bridge::build(bridge_config, &password, &password_sink, None)
            .await
            .unwrap();

    if !https_address.is_empty() {
        let https_address = https_address.parse::<SocketAddr>().unwrap();

        tokio::spawn(redirect_http_to_https(
            https_address.port(),
            listener_http,
        ));
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();

        let tls = RustlsConfig::from_pem_file(
            PathBuf::from(&build_https_cert()),
            PathBuf::from(&build_https_private_key()),
        )
        .await
        .unwrap();

        let handle = Handle::new();

        let handle_clone = handle.clone();
        tokio::spawn(async move {
            join_all(runners).await;
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
            info!(TARGET_HTTP, "All the runners have stopped");
        });

        axum_server::bind_rustls(https_address, tls)
            .handle(handle_clone)
            .serve(
                tower_trace(build_routes(bridge, auth_db))
                    .layer(cors)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
    } else {
        axum::serve(
            listener_http,
            tower_trace(build_routes(bridge, auth_db))
                .layer(cors)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            join_all(runners).await;
            info!(TARGET_HTTP, "All the runners have stopped");
        })
        .await
        .unwrap()
    }
}

fn load_auth_config(path: String) -> Option<AuthConfig> {
    if path.is_empty() {
        return None;
    }

    let content = std::fs::read_to_string(&path).ok()?;

    #[derive(Deserialize)]
    struct AuthWrapper {
        auth: AuthConfig,
    }

    toml::from_str::<AuthWrapper>(&content)
        .map(|w| w.auth)
        .or_else(|_| toml::from_str::<AuthConfig>(&content))
        .ok()
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
        http: listener_http.local_addr().unwrap().port().to_string(),
    };

    let redirect = move |Host(host): Host, uri: Uri| async move {
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
        .unwrap();
}
