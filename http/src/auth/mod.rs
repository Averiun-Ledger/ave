// Ave HTTP Auth System
//
// Complete authentication and authorization system with:
// - Users, roles, and permissions
// - API key management with expiration
// - Audit logging
// - Rate limiting
// - Account lockout
// - SQLite-based storage

pub mod crypto;
pub mod database;
mod database_apikeys;
mod database_audit;
mod database_ext;
pub mod middleware;
pub mod models;

// Handler modules
pub mod admin_handlers;
pub mod apikey_handlers;
pub mod integration;
pub mod login_handler;
pub mod system_handlers;

use ave_bridge::auth::PasswordPolicy;
// Re-exports for convenience
pub use database::AuthDatabase;


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
    use ave_bridge::auth::{AuthConfig, PasswordPolicy};

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
