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

// Re-exports for convenience
pub use database::AuthDatabase;

const MIN_LENGTH: usize = 8;
const REQUIRE_UPPERCASE: bool = true;
const REQUIRE_LOWERCASE: bool = true;
const REQUIRE_DIGIT: bool = true;
const REQUIRE_SPECIAL: bool = true;

/// Validate password against policy
pub fn validate_password(
    password: &str,
) -> Result<(), String> {
    if password.len() < MIN_LENGTH {
        return Err(format!(
            "Password must be at least {} characters long",
            MIN_LENGTH
        ));
    }

    if REQUIRE_UPPERCASE && !password.chars().any(|c| c.is_uppercase()) {
        return Err(
            "Password must contain at least one uppercase letter".to_string()
        );
    }

    if REQUIRE_LOWERCASE && !password.chars().any(|c| c.is_lowercase()) {
        return Err(
            "Password must contain at least one lowercase letter".to_string()
        );
    }

    if REQUIRE_DIGIT && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".to_string());
    }

    if REQUIRE_SPECIAL && !password.chars().any(|c| !c.is_alphanumeric())
    {
        return Err(
            "Password must contain at least one special character".to_string()
        );
    }

    Ok(())
}