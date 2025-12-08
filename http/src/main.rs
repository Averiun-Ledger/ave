use std::{net::SocketAddr, path::PathBuf, time::Duration};

use auth::{
    AuthDatabase,
    integration::{
        cleanup_old_data, initialize_auth_database, log_auth_statistics,
    },
};
use ave_bridge::{
    Bridge, auth::AuthConfig, clap::Parser, settings::{
        build_config,
        command::{
            Args, build_auth_password, build_config_path, build_key_password,
            build_sink_password,
        },
    }
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
use futures::future::join_all;
use middleware::tower_trace;
use server::build_routes;
use std::sync::Arc;
use tokio::{net::TcpListener, time::interval};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

use crate::auth::build_auth;

mod auth;
mod config_types;
mod doc;
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

    let mut config_path = args.config_path;
    if config_path.is_empty() {
        config_path = build_config_path();
    }

    let config = build_config(&config_path)
        .map_err(|e| {
            error!("Can not build config: {}", e);
        })
        .expect("Can not build config");

    let listener_http = tokio::net::TcpListener::bind(&config.http.http_address)
        .await
        .expect("Can not build TCP listener with http address");

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

    let _log_handle = logging::init_logging(&config.logging).await;

    let auth_db: Option<Arc<AuthDatabase>> = build_auth(&config.auth, &args.auth_password).await;

    let mut key_password = args.key_password;
    if key_password.is_empty() {
        key_password = build_key_password();
    }

    let mut sink_password = args.sink_password;
    if sink_password.is_empty() {
        sink_password = build_sink_password();
    }

    let (bridge, runners) =
        Bridge::build(&config, &key_password, &sink_password, None)
            .await.map_err(|e| {
                error!("Can not build Bridge: {}", e);
            }).expect("Can not build Bridge");

    if let Some(https_address) = config.http.https_address {
        let https_address = https_address.parse::<SocketAddr>().expect("Can not parse Https address as SocketAddr");

        tokio::spawn(redirect_http_to_https(
            https_address.port(),
            listener_http,
        ));
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Can not install ring for RustTLS");

        let (cert, private_key) = match (config.http.https_cert_path, config.http.https_private_key_path) {
            (Some(cert), Some(private_key)) => (cert, private_key),
            _ => {
                error!("Https must have cert and private key");
                return;
            }
        };


        let tls = RustlsConfig::from_pem_file(
            PathBuf::from(&cert),
            PathBuf::from(&private_key),
        )
        .await.expect("Can not build tls");

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
                tower_trace(build_routes(config.http.enable_doc, bridge, auth_db))
                    .layer(cors)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("Can not run axum server");
    } else {
        axum::serve(
            listener_http,
            tower_trace(build_routes(config.http.enable_doc, bridge, auth_db))
                .layer(cors)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            join_all(runners).await;
            info!(TARGET_HTTP, "All the runners have stopped");
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
        http: listener_http.local_addr().expect("Invalid listener http").port().to_string(),
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
        .expect("Can not run axum server, redirect http to https");
}
