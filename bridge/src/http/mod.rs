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
    pub proxy: ProxyConfig,
    pub cors: CorsConfig,
    /// Self-signed certificate configuration for automatic TLS
    pub self_signed_cert: SelfSignedCertConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Trusted proxy CIDRs or IPs allowed to provide forwarded client IP headers.
    pub trusted_proxies: Vec<String>,
    /// Trust X-Forwarded-For when the direct peer is a trusted proxy.
    pub trust_x_forwarded_for: bool,
    /// Trust X-Real-IP when the direct peer is a trusted proxy.
    pub trust_x_real_ip: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SelfSignedCertConfig {
    /// Enable automatic self-signed certificate generation.
    /// When enabled, uses https_cert_path and https_private_key_path for output.
    pub enabled: bool,
    /// Common Name for the certificate (e.g., "localhost", "ave.local")
    pub common_name: String,
    /// Subject Alternative Names (additional hostnames/IPs)
    pub san: Vec<String>,
    /// Certificate validity in days
    pub validity_days: u32,
    /// Days before expiration to trigger renewal
    pub renew_before_days: u32,
    /// Check interval in seconds for certificate expiration
    pub check_interval_secs: u64,
}

impl Default for SelfSignedCertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            common_name: "localhost".to_string(),
            san: vec!["127.0.0.1".to_string(), "::1".to_string()],
            validity_days: 365,
            renew_before_days: 30,
            check_interval_secs: 3600, // Check every hour
        }
    }
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
            proxy: ProxyConfig::default(),
            cors: CorsConfig::default(),
            self_signed_cert: SelfSignedCertConfig::default(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            trust_x_forwarded_for: true,
            trust_x_real_ip: true,
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
