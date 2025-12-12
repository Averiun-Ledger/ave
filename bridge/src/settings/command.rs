use std::env;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Path to the file containing the settings you want to use
    #[arg(short = 'c', long, default_value_t = String::default())]
    pub config_path: String,

    /// Password to be used for the creation of the cryptographic material, if not specified, the password of the environment variable 'AVE_PASSWORD' will be used.
    #[arg(short = 'k', long, default_value_t = String::default())]
    pub key_password: String,

    /// Password to be used for the creation of the cryptographic material, if not specified, the password of the environment variable 'AVE_PASSWORD' will be used.
    #[arg(short = 'a', long, default_value_t = String::default())]
    pub auth_password: String,

    /// Password to be used to auth for sinks.
    #[arg(short = 's', long, default_value_t = String::default())]
    pub sink_password: String,
}

pub fn build_sink_password() -> String {
    env::var("AVE_SINK_PASSWORD").unwrap_or_default()
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
