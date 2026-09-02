//! `ave-compiler` binary: configurable gRPC contract compiler service.

use std::process::ExitCode;

use ave_core::compilation::service::CompilerServer;
use ave_core::compilation::service_config::ServiceConfig;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// Environment variable with the configuration file path; the `--config`
/// argument takes precedence.
const CONFIG_ENV_VAR: &str = "AVE_COMPILER_CONFIG";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = parse_config_path();
    let config = match ServiceConfig::load(&config_path) {
        Ok(config) => config,
        Err(error) => {
            error!(
                file = %config_path,
                error = %error,
                "Failed to load compiler configuration"
            );
            return ExitCode::FAILURE;
        }
    };

    info!(
        listen_addr = %config.listen_addr,
        tls = config.tls.is_some(),
        api_keys = config.api_keys.len(),
        artifacts_dir = %config.artifacts_dir.display(),
        work_dir = %config.work_dir.display(),
        "Starting compiler service"
    );

    let server = match CompilerServer::new(config.clone()).await {
        Ok(server) => server,
        Err(error) => {
            error!(error = %error, "Failed to start compiler service");
            return ExitCode::FAILURE;
        }
    };

    info!(
        public_key = %server.public_key(),
        "Compiler identity loaded; pin this key in the node configuration \
         to verify attestations"
    );

    let listener = match std::net::TcpListener::bind(&config.listen_addr) {
        Ok(listener) => listener,
        Err(error) => {
            error!(
                addr = %config.listen_addr,
                error = %error,
                "Failed to bind compiler listener"
            );
            return ExitCode::FAILURE;
        }
    };

    let shutdown = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(error = %error, "Failed to listen for shutdown signal");
        }
    };

    if let Err(error) = server.serve(listener, shutdown).await {
        error!(error = %error, "Compiler service failed");
        return ExitCode::FAILURE;
    }

    info!("Compiler service shut down");
    ExitCode::SUCCESS
}

/// Resolves the configuration file path: first `--config <path>` argument
/// wins, then the `AVE_COMPILER_CONFIG` environment variable, then the
/// default `compiler-config` name (any of the extensions supported by the
/// `config` crate).
fn parse_config_path() -> String {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config"
            && let Some(path) = args.next()
        {
            return path;
        }
        if let Some(path) = arg.strip_prefix("--config=") {
            return path.to_owned();
        }
    }
    std::env::var(CONFIG_ENV_VAR)
        .unwrap_or_else(|_| "compiler-config".to_owned())
}
