// Ave HTTP Auth System - Configuration
//
// This module defines the configuration structure for the authentication system

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Authentication system configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    /// Enable or disable authentication
    /// If false, all endpoints are accessible without authentication
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Path to the SQLite database file
    #[serde(default = "default_database_path")]
    pub database_path: PathBuf,

    /// Superadmin bootstrap credentials
    /// Only used on first run to create initial superadmin account
    pub superadmin: Option<SuperadminConfig>,

    /// Password policy settings
    #[serde(default)]
    pub password_policy: PasswordPolicy,

    /// API key settings
    #[serde(default)]
    pub api_key: ApiKeyConfig,

    /// Account lockout settings
    #[serde(default)]
    pub lockout: LockoutConfig,

    /// Rate limiting settings
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Session settings
    #[serde(default)]
    pub session: SessionConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            database_path: default_database_path(),
            superadmin: None,
            password_policy: PasswordPolicy::default(),
            api_key: ApiKeyConfig::default(),
            lockout: LockoutConfig::default(),
            rate_limit: RateLimitConfig::default(),
            session: SessionConfig::default(),
        }
    }
}

fn default_enabled() -> bool {
    false
}

fn default_database_path() -> PathBuf {
    PathBuf::from("./data/auth.db")
}

/// Superadmin bootstrap configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuperadminConfig {
    /// Initial superadmin username
    pub username: String,

    /// Initial superadmin password
    /// This should be changed immediately after first login
    pub password: String,
}

/// Password policy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PasswordPolicy {
    /// Minimum password length
    #[serde(default = "default_min_length")]
    pub min_length: usize,

    /// Require at least one uppercase letter
    #[serde(default = "default_require_uppercase")]
    pub require_uppercase: bool,

    /// Require at least one lowercase letter
    #[serde(default = "default_require_lowercase")]
    pub require_lowercase: bool,

    /// Require at least one digit
    #[serde(default = "default_require_digit")]
    pub require_digit: bool,

    /// Require at least one special character
    #[serde(default = "default_require_special")]
    pub require_special: bool,

    /// Password expiration in days (0 = never expires)
    #[serde(default)]
    pub expiration_days: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: default_min_length(),
            require_uppercase: default_require_uppercase(),
            require_lowercase: default_require_lowercase(),
            require_digit: default_require_digit(),
            require_special: default_require_special(),
            expiration_days: 0,
        }
    }
}

fn default_min_length() -> usize {
    8
}

fn default_require_uppercase() -> bool {
    false
}

fn default_require_lowercase() -> bool {
    false
}

fn default_require_digit() -> bool {
    false
}

fn default_require_special() -> bool {
    false
}

/// API key configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiKeyConfig {
    /// Default TTL for API keys in seconds
    /// 0 = no expiration
    #[serde(default = "default_api_key_ttl")]
    pub default_ttl_seconds: i64,

    /// Maximum number of API keys per user
    /// 0 = unlimited
    #[serde(default = "default_max_keys_per_user")]
    pub max_keys_per_user: u32,

    /// Allow custom key prefixes
    #[serde(default = "default_allow_custom_prefix")]
    pub allow_custom_prefix: bool,

    /// Automatically revoke keys when user role changes
    #[serde(default = "default_revoke_on_role_change")]
    pub revoke_on_role_change: bool,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: default_api_key_ttl(),
            max_keys_per_user: default_max_keys_per_user(),
            allow_custom_prefix: default_allow_custom_prefix(),
            revoke_on_role_change: default_revoke_on_role_change(),
        }
    }
}

fn default_api_key_ttl() -> i64 {
    2592000 // 30 days
}

fn default_max_keys_per_user() -> u32 {
    10
}

fn default_allow_custom_prefix() -> bool {
    false
}

fn default_revoke_on_role_change() -> bool {
    true
}

/// Account lockout configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LockoutConfig {
    /// Maximum failed login attempts before lockout
    /// 0 = no lockout
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Lockout duration in seconds
    #[serde(default = "default_lockout_duration")]
    pub duration_seconds: i64,

    /// Reset failed attempts count after successful login
    #[serde(default = "default_reset_on_success")]
    pub reset_on_success: bool,
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            duration_seconds: default_lockout_duration(),
            reset_on_success: default_reset_on_success(),
        }
    }
}

fn default_max_attempts() -> u32 {
    5
}

fn default_lockout_duration() -> i64 {
    900 // 15 minutes
}

fn default_reset_on_success() -> bool {
    true
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,

    /// Time window in seconds
    #[serde(default = "default_window_seconds")]
    pub window_seconds: i64,

    /// Maximum requests per window
    #[serde(default = "default_max_requests")]
    pub max_requests: u32,

    /// Rate limit by API key
    #[serde(default = "default_limit_by_key")]
    pub limit_by_key: bool,

    /// Rate limit by IP address
    #[serde(default = "default_limit_by_ip")]
    pub limit_by_ip: bool,

    /// Cleanup old rate limit entries interval in seconds
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_seconds: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            window_seconds: default_window_seconds(),
            max_requests: default_max_requests(),
            limit_by_key: default_limit_by_key(),
            limit_by_ip: default_limit_by_ip(),
            cleanup_interval_seconds: default_cleanup_interval(),
        }
    }
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_window_seconds() -> i64 {
    60
}

fn default_max_requests() -> u32 {
    100
}

fn default_limit_by_key() -> bool {
    true
}

fn default_limit_by_ip() -> bool {
    true
}

fn default_cleanup_interval() -> i64 {
    3600 // 1 hour
}

/// Session configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    /// Enable audit logging
    #[serde(default = "default_audit_enabled")]
    pub audit_enabled: bool,

    /// Audit log retention in days (0 = keep forever)
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u32,

    /// Log successful authentication attempts
    #[serde(default = "default_log_success")]
    pub log_success: bool,

    /// Log failed authentication attempts
    #[serde(default = "default_log_failures")]
    pub log_failures: bool,

    /// Log all API calls
    #[serde(default = "default_log_all_requests")]
    pub log_all_requests: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            audit_enabled: default_audit_enabled(),
            audit_retention_days: default_audit_retention_days(),
            log_success: default_log_success(),
            log_failures: default_log_failures(),
            log_all_requests: default_log_all_requests(),
        }
    }
}

fn default_audit_enabled() -> bool {
    true
}

fn default_audit_retention_days() -> u32 {
    90
}

fn default_log_success() -> bool {
    true
}

fn default_log_failures() -> bool {
    true
}

fn default_log_all_requests() -> bool {
    false
}

/// Validate password against policy
pub fn validate_password(
    password: &str,
    policy: &PasswordPolicy,
) -> Result<(), String> {
    if password.len() < policy.min_length {
        return Err(format!(
            "Password must be at least {} characters long",
            policy.min_length
        ));
    }

    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err(
            "Password must contain at least one uppercase letter".to_string()
        );
    }

    if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err(
            "Password must contain at least one lowercase letter".to_string()
        );
    }

    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".to_string());
    }

    if policy.require_special && !password.chars().any(|c| !c.is_alphanumeric())
    {
        return Err(
            "Password must contain at least one special character".to_string()
        );
    }

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuthConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.password_policy.min_length, 8);
    }

    #[test]
    fn test_password_validation_length() {
        let policy = PasswordPolicy {
            min_length: 10,
            ..Default::default()
        };

        assert!(validate_password("short", &policy).is_err());
        assert!(validate_password("longenough", &policy).is_ok());
    }

    #[test]
    fn test_password_validation_uppercase() {
        let policy = PasswordPolicy {
            min_length: 1,
            require_uppercase: true,
            ..Default::default()
        };

        assert!(validate_password("lowercase", &policy).is_err());
        assert!(validate_password("Uppercase", &policy).is_ok());
    }

    #[test]
    fn test_password_validation_digit() {
        let policy = PasswordPolicy {
            min_length: 1,
            require_digit: true,
            ..Default::default()
        };

        assert!(validate_password("nodigits", &policy).is_err());
        assert!(validate_password("with1digit", &policy).is_ok());
    }

    #[test]
    fn test_password_validation_special() {
        let policy = PasswordPolicy {
            min_length: 1,
            require_special: true,
            ..Default::default()
        };

        assert!(validate_password("nospecial", &policy).is_err());
        assert!(validate_password("with!special", &policy).is_ok());
    }

    #[test]
    fn test_password_validation_all_requirements() {
        let policy = PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            expiration_days: 0,
        };

        assert!(validate_password("weak", &policy).is_err());
        assert!(validate_password("StrongPass123!", &policy).is_ok());
    }
}
