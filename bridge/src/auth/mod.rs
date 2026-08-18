// Ave HTTP Auth System - Configuration
//
// This module defines the configuration structure for the authentication system

use ave_common::Error;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Authentication system configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Enable or disable authentication
    /// If false, all endpoints are accessible without authentication
    pub enable: bool,

    /// Path to the SQLite database file
    pub database_path: PathBuf,

    /// Durable writes: PRAGMA synchronous=FULL (true) vs NORMAL (false).
    pub durability: bool,

    /// Superadmin bootstrap credentials
    /// Only used on first run to create initial superadmin account
    pub superadmin: String,

    /// API key settings
    pub api_key: ApiKeyConfig,

    /// Account lockout settings
    pub lockout: LockoutConfig,

    /// Rate limiting settings
    pub rate_limit: RateLimitConfig,

    /// Session settings
    pub session: SessionConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enable: false,
            database_path: PathBuf::from("auth"),
            durability: false,
            superadmin: String::default(),
            api_key: ApiKeyConfig::default(),
            lockout: LockoutConfig::default(),
            rate_limit: RateLimitConfig::default(),
            session: SessionConfig::default(),
        }
    }
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.database_path.as_os_str().is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "auth.database_path".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if self.enable && self.superadmin.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "auth.superadmin".to_string(),
                reason: "must not be empty when auth is enabled".to_string(),
            });
        }

        self.api_key
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "auth.api_key".to_string(),
                reason: e.to_string(),
            })?;
        self.lockout
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "auth.lockout".to_string(),
                reason: e.to_string(),
            })?;
        self.rate_limit.validate().map_err(|e| {
            Error::InvalidConfiguration {
                component: "auth.rate_limit".to_string(),
                reason: e.to_string(),
            }
        })?;
        self.session
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "auth.session".to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }
}

/// API key configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ApiKeyConfig {
    /// Default TTL for API keys in seconds
    /// 0 = no expiration
    pub default_ttl_seconds: i64,

    /// Maximum number of API keys per user
    /// 0 = unlimited
    pub max_keys_per_user: u32,

    /// Prefix used when generating API keys
    pub prefix: String,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 2592000,
            max_keys_per_user: 10,
            prefix: "ave_node_".to_string(),
        }
    }
}

impl ApiKeyConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.default_ttl_seconds < 0 {
            return Err(Error::InvalidConfiguration {
                component: "auth.api_key.default_ttl_seconds".to_string(),
                reason: "must not be negative".to_string(),
            });
        }
        if self.prefix.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "auth.api_key.prefix".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Account lockout configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct LockoutConfig {
    /// Maximum failed login attempts before lockout
    /// 0 = no lockout
    pub max_attempts: u32,

    /// Lockout duration in seconds
    pub duration_seconds: i64,
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            duration_seconds: 300,
        }
    }
}

impl LockoutConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_attempts > 0 && self.duration_seconds <= 0 {
            return Err(Error::InvalidConfiguration {
                component: "auth.lockout.duration_seconds".to_string(),
                reason: "must be greater than zero when lockout is enabled (max_attempts > 0)"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enable: bool,

    /// Time window in seconds (default for all endpoints)
    pub window_seconds: i64,

    /// Maximum requests per window (default for all endpoints)
    pub max_requests: u32,

    /// Rate limit by API key
    pub limit_by_key: bool,

    /// Rate limit by IP address
    pub limit_by_ip: bool,

    /// Cleanup old rate limit entries interval in seconds
    pub cleanup_interval_seconds: i64,

    /// Sensitive endpoints with stricter rate limits
    /// Map of endpoint path to EndpointRateLimit
    #[serde(default)]
    pub sensitive_endpoints: Vec<EndpointRateLimit>,
}

/// Rate limit configuration for a specific endpoint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EndpointRateLimit {
    /// Endpoint path (e.g., "/login", "/change-password")
    pub endpoint: String,

    /// Maximum requests per window for this endpoint
    pub max_requests: u32,

    /// Optional: Custom window size for this endpoint (None = use default)
    pub window_seconds: Option<i64>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enable: true,
            window_seconds: 60,
            max_requests: 100,
            limit_by_key: true,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
            // Default sensitive endpoints with stricter limits
            sensitive_endpoints: vec![
                EndpointRateLimit {
                    endpoint: "/login".to_string(),
                    max_requests: 10,
                    window_seconds: None, // Use default 60 seconds
                },
                EndpointRateLimit {
                    endpoint: "/change-password".to_string(),
                    max_requests: 5,
                    window_seconds: None,
                },
                EndpointRateLimit {
                    endpoint: "/admin/users".to_string(),
                    max_requests: 20,
                    window_seconds: None,
                },
            ],
        }
    }
}

impl RateLimitConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.enable {
            return Ok(());
        }
        if self.window_seconds <= 0 {
            return Err(Error::InvalidConfiguration {
                component: "auth.rate_limit.window_seconds".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_requests == 0 {
            return Err(Error::InvalidConfiguration {
                component: "auth.rate_limit.max_requests".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if !self.limit_by_key && !self.limit_by_ip {
            return Err(Error::InvalidConfiguration {
                component: "auth.rate_limit".to_string(),
                reason: "at least one of limit_by_key or limit_by_ip must be true when rate limiting is enabled"
                    .to_string(),
            });
        }
        if self.cleanup_interval_seconds <= 0 {
            return Err(Error::InvalidConfiguration {
                component: "auth.rate_limit.cleanup_interval_seconds"
                    .to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }

        let mut seen = std::collections::HashSet::new();
        for (i, endpoint) in self.sensitive_endpoints.iter().enumerate() {
            endpoint
                .validate()
                .map_err(|e| Error::InvalidConfiguration {
                    component: format!(
                        "auth.rate_limit.sensitive_endpoints[{i}]"
                    ),
                    reason: e.to_string(),
                })?;
            if !seen.insert(&endpoint.endpoint) {
                return Err(Error::InvalidConfiguration {
                    component: format!(
                        "auth.rate_limit.sensitive_endpoints[{i}].endpoint"
                    ),
                    reason: format!("duplicated value '{}'", endpoint.endpoint),
                });
            }
        }
        Ok(())
    }
}

impl EndpointRateLimit {
    pub fn validate(&self) -> Result<(), Error> {
        if self.endpoint.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "EndpointRateLimit.endpoint".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if !self.endpoint.starts_with('/') {
            return Err(Error::InvalidConfiguration {
                component: "EndpointRateLimit.endpoint".to_string(),
                reason: format!("must start with '/', got {}", self.endpoint),
            });
        }
        if self.max_requests == 0 {
            return Err(Error::InvalidConfiguration {
                component: "EndpointRateLimit.max_requests".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if let Some(window) = self.window_seconds
            && window <= 0
        {
            return Err(Error::InvalidConfiguration {
                component: "EndpointRateLimit.window_seconds".to_string(),
                reason: "must be greater than zero when set".to_string(),
            });
        }
        Ok(())
    }
}

/// Session configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Enable audit logging
    pub audit_enable: bool,

    /// Audit log retention in days (0 = keep forever)
    pub audit_retention_days: u32,

    /// Maximum number of audit logs to keep (0 = unlimited)
    /// When exceeded, oldest logs are deleted (LRU cache behavior)
    pub audit_max_entries: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            audit_enable: true,
            audit_retention_days: 90,
            // Limit to 1 million entries (prevents unbounded growth)
            // Approximately 11.5 days at 1 req/sec, or 1 day at 11.5 req/sec
            audit_max_entries: 1_000_000,
        }
    }
}

impl SessionConfig {
    pub const fn validate(&self) -> Result<(), Error> {
        // audit_retention_days == 0 means keep forever; audit_max_entries == 0 means unlimited.
        // Both are valid defensive values, so no further validation is needed.
        Ok(())
    }
}
