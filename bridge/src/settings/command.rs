use std::env;

use clap::{ArgAction, Parser};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Path to the file containing the settings you want to use
    #[arg(short = 'c', long, default_value_t = String::default())]
    pub config_path: String,

    /// Password for the node's cryptographic material. If omitted, the
    /// 'AVE_KEY_PASSWORD' environment variable is used (preferred: CLI flags
    /// are visible in the process list).
    #[arg(short = 'k', long, default_value_t = String::default())]
    pub key_password: String,

    /// Password for the authentication system bootstrap. If omitted, the
    /// 'AVE_AUTH_PASSWORD' environment variable is used (preferred: CLI flags
    /// are visible in the process list).
    #[arg(short = 'a', long, default_value_t = String::default())]
    pub auth_password: String,

    /// Password to be used to auth for sinks. If omitted, the
    /// 'AVE_SINK_PASSWORD' environment variable is used (preferred).
    #[arg(short = 's', long, default_value_t = String::default())]
    pub sink_password: String,

    /// API key to be used for sink authentication (alternative to password-based auth).
    /// If omitted, the 'AVE_SINK_API_KEY' environment variable is used (preferred).
    #[arg(short = 'S', long, default_value_t = String::default())]
    pub sink_api_key: String,

    /// Start the node in safe mode, disabling mutating operations.
    #[arg(short = 'm', long, action = ArgAction::SetTrue)]
    pub safe_mode: bool,
}

pub fn build_sink_password() -> String {
    env::var("AVE_SINK_PASSWORD").unwrap_or_default()
}

pub fn build_sink_api_key() -> String {
    env::var("AVE_SINK_API_KEY").unwrap_or_default()
}

pub fn build_auth_password() -> String {
    env::var("AVE_AUTH_PASSWORD").unwrap_or_default()
}

pub fn build_key_password() -> String {
    env::var("AVE_KEY_PASSWORD").unwrap_or_default()
}

pub fn build_config_path() -> String {
    env::var("AVE_CONFIG").unwrap_or_default()
}

pub fn build_safe_mode() -> Option<bool> {
    let value = env::var("AVE_SAFE_MODE").ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}
