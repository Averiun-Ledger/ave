use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    pub http_address: String,
    pub https_address: Option<String>,
    pub https_cert_path: Option<PathBuf>,
    pub https_private_key_path: Option<PathBuf>,
    pub enable_doc: bool,
    pub cors: CorsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CorsConfig {
    /// Enable CORS middleware
    pub enabled: bool,
    /// Allow all origins (*). If false, use `allowed_origins` list
    /// SECURITY WARNING: Setting this to true (default) allows ANY website to make requests
    /// This is a CVSS 6.5 vulnerability if you plan to access the API from browsers
    /// For production with web frontend, set to false and specify `allowed_origins`
    pub allow_any_origin: bool,
    /// List of allowed origins (only used if `allow_any_origin` is false)
    /// Example: ["https://app.example.com", "https://dashboard.example.com"]
    pub allowed_origins: Vec<String>,
    /// Allow credentials (cookies, authorization headers) in CORS requests
    /// SECURITY: Should be false if `allow_any_origin` is true
    pub allow_credentials: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            http_address: "0.0.0.0:3000".to_string(),
            https_address: Default::default(),
            https_cert_path: Default::default(),
            https_private_key_path: Default::default(),
            enable_doc: Default::default(),
            cors: CorsConfig::default(),
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_any_origin: true,
            allowed_origins: vec![],
            allow_credentials: false,
        }
    }
}
