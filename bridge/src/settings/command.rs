use clap::{Parser, command};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Path to the file containing the settings you want to use
    #[arg(short = 'c', long, default_value_t = String::default())]
    pub config_path: String,

    #[arg(short = 'a', long, default_value_t = String::default())]
    pub auth_config_path: String,

    /// Bulean to indicate whether you want to use the environment variables as a configuration (file_path compatible)
    #[arg(short = 'e' , long, default_value_t = true)]
    pub env_config: bool,

    /// Password to be used for the creation of the cryptographic material, if not specified, the password of the environment variable 'AVE_PASSWORD' will be used.
    #[arg(short = 'p', long, default_value_t = String::default())]
    pub password: String,

    /// Password to be used to auth for sinks.
    #[arg(short = 's', long, default_value_t = String::default())]
    pub password_sink: String,
}
