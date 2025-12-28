// Ave HTTP Auth System - Configuration
//
// This module defines the configuration structure for the authentication system

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
            superadmin: String::default(),
            api_key: ApiKeyConfig::default(),
            lockout: LockoutConfig::default(),
            rate_limit: RateLimitConfig::default(),
            session: SessionConfig::default(),
        }
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
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 2592000,
            max_keys_per_user: 10,
        }
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

/// Session configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Enable audit logging
    pub audit_enable: bool,

    /// Audit log retention in days (0 = keep forever)
    pub audit_retention_days: u32,

    /// Log all API calls
    pub log_all_requests: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            audit_enable: true,
            audit_retention_days: 90,
            log_all_requests: false,
        }
    }
}
