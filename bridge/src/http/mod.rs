use std::path::PathBuf;

use ave_common::Error;
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

impl SelfSignedCertConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }
        if self.common_name.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "http.self_signed_cert.common_name".to_string(),
                reason: "must not be empty when self-signed certificates are enabled"
                    .to_string(),
            });
        }
        if self.san.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "http.self_signed_cert.san".to_string(),
                reason: "must not be empty when self-signed certificates are enabled"
                    .to_string(),
            });
        }
        for (i, san) in self.san.iter().enumerate() {
            if san.is_empty() {
                return Err(Error::InvalidConfiguration {
                    component: format!(
                        "http.self_signed_cert.san[{i}]"
                    ),
                    reason: "must not be empty when self-signed certificates are enabled"
                        .to_string(),
                });
            }
        }
        if self.validity_days == 0 {
            return Err(Error::InvalidConfiguration {
                component: "http.self_signed_cert.validity_days".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.renew_before_days == 0 {
            return Err(Error::InvalidConfiguration {
                component: "http.self_signed_cert.renew_before_days"
                    .to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.renew_before_days >= self.validity_days {
            return Err(Error::InvalidConfiguration {
                component: "http.self_signed_cert.renew_before_days"
                    .to_string(),
                reason: format!(
                    "must be less than validity_days ({})",
                    self.validity_days
                ),
            });
        }
        if self.check_interval_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "http.self_signed_cert.check_interval_secs"
                    .to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
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

impl HttpConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.http_address.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "http.http_address".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        let https_enabled =
            self.https_address.is_some() || self.self_signed_cert.enabled;

        if let Some(addr) = &self.https_address 
            && addr.is_empty() {
                return Err(Error::InvalidConfiguration {
                    component: "http.https_address".to_string(),
                    reason: "must not be empty when set".to_string(),
                });
            }
        

        if https_enabled {
            if self.https_cert_path.is_none() {
                return Err(Error::InvalidConfiguration {
                    component: "http.https_cert_path".to_string(),
                    reason: "must be set when HTTPS is enabled".to_string(),
                });
            }
            if self.https_private_key_path.is_none() {
                return Err(Error::InvalidConfiguration {
                    component: "http.https_private_key_path".to_string(),
                    reason: "must be set when HTTPS is enabled".to_string(),
                });
            }
        }

        self.proxy
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "http.proxy".to_string(),
                reason: e.to_string(),
            })?;
        self.cors
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "http.cors".to_string(),
                reason: e.to_string(),
            })?;
        self.self_signed_cert.validate().map_err(|e| {
            Error::InvalidConfiguration {
                component: "http.self_signed_cert".to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(())
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

impl ProxyConfig {
    pub fn validate(&self) -> Result<(), Error> {
        for (i, proxy) in self.trusted_proxies.iter().enumerate() {
            if proxy.is_empty() {
                return Err(Error::InvalidConfiguration {
                    component: format!("http.proxy.trusted_proxies[{i}]"),
                    reason: "must not be empty".to_string(),
                });
            }
        }
        Ok(())
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

impl CorsConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.allow_any_origin && self.allowed_origins.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "http.cors.allowed_origins".to_string(),
                reason: "must not be empty when allow_any_origin is false"
                    .to_string(),
            });
        }
        for (i, origin) in self.allowed_origins.iter().enumerate() {
            if origin.is_empty() {
                return Err(Error::InvalidConfiguration {
                    component: format!("http.cors.allowed_origins[{i}]"),
                    reason: "must not be empty".to_string(),
                });
            }
        }
        Ok(())
    }
}
