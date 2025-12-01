// Ave HTTP Auth System - Cryptographic Functions
//
// This module provides password hashing with Argon2 and API key generation/hashing

use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        rand_core::OsRng,
    },
};
use sha2::{Digest, Sha256};

/// Result type for crypto operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Errors that can occur during cryptographic operations
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Password hashing failed: {0}")]
    HashError(String),

    #[error("Password verification failed: {0}")]
    VerifyError(String),

    #[error("Invalid password hash format")]
    InvalidHashFormat,
}

// =============================================================================
// PASSWORD HASHING WITH ARGON2
// =============================================================================

/// Hash a password using Argon2id
///
/// Argon2id is the recommended variant as it provides resistance to both
/// side-channel and GPU-based attacks.
///
/// # Arguments
/// * `password` - The plain-text password to hash
///
/// # Returns
/// * `CryptoResult<String>` - The hashed password in PHC format
pub fn hash_password(password: &str) -> CryptoResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| CryptoError::HashError(e.to_string()))
}

/// Verify a password against a hash
///
/// # Arguments
/// * `password` - The plain-text password to verify
/// * `hash` - The stored password hash in PHC format
///
/// # Returns
/// * `CryptoResult<bool>` - true if password matches, false otherwise
pub fn verify_password(password: &str, hash: &str) -> CryptoResult<bool> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|_| CryptoError::InvalidHashFormat)?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(CryptoError::VerifyError(e.to_string())),
    }
}

// =============================================================================
// API KEY GENERATION AND HASHING
// =============================================================================

/// Generate a new API key with prefix
///
/// Format: ave_v1_<40 random hex chars>
/// Example: ave_v1_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
///
/// The key is 20 bytes (160 bits) of randomness encoded as 40 hex characters.
///
/// # Returns
/// * `String` - The generated API key
pub fn generate_api_key() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 20] = rng.r#gen();
    let random_hex = hex::encode(random_bytes);

    format!("ave_v1_{}", random_hex)
}

/// Generate an API key with a custom prefix
///
/// # Arguments
/// * `prefix` - Custom prefix to use (e.g., "test", "prod", "dev")
///
/// # Returns
/// * `String` - The generated API key with custom prefix
pub fn generate_api_key_with_prefix(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 20] = rng.r#gen();
    let random_hex = hex::encode(random_bytes);

    format!("ave_v1_{}_{}", prefix, random_hex)
}

/// Extract the visible prefix from an API key
///
/// Returns the first 11 characters (ave_v1_XXX) for logging and identification
///
/// # Arguments
/// * `api_key` - The full API key
///
/// # Returns
/// * `String` - The visible prefix
pub fn extract_key_prefix(api_key: &str) -> String {
    if api_key.len() >= 11 {
        api_key[..11].to_string()
    } else {
        api_key.to_string()
    }
}

/// Hash an API key using SHA-256
///
/// The hash is used for secure storage in the database.
///
/// # Arguments
/// * `api_key` - The plain-text API key
///
/// # Returns
/// * `String` - The SHA-256 hash in hex format
pub fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "MySecurePassword123!";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_password_hash_format() {
        let password = "test";
        let hash = hash_password(password).unwrap();

        // Argon2 PHC format starts with $argon2
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn test_invalid_hash_format() {
        let result = verify_password("test", "invalid_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_api_key_generation() {
        let key = generate_api_key();

        // Check format
        assert!(key.starts_with("ave_v1_"));
        // Length should be 7 (prefix) + 40 (hex) = 47
        assert_eq!(key.len(), 47);
    }

    #[test]
    fn test_api_key_with_custom_prefix() {
        let key = generate_api_key_with_prefix("test");

        assert!(key.starts_with("ave_v1_test_"));
    }

    #[test]
    fn test_api_key_uniqueness() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_extract_key_prefix() {
        let key = "ave_v1_abcdef1234567890";
        let prefix = extract_key_prefix(&key);

        assert_eq!(prefix, "ave_v1_abcd"); // 11 characters
    }

    #[test]
    fn test_api_key_hashing() {
        let key = generate_api_key();
        let hash = hash_api_key(&key);

        // SHA-256 hex hash should be 64 characters
        assert_eq!(hash.len(), 64);

        // Verify the key
        assert_eq!(hash_api_key(&key), hash);
        assert_ne!(hash_api_key("wrong_key"), hash);
    }

    #[test]
    fn test_api_key_hash_deterministic() {
        let key = "ave_v1_test123";
        let hash1 = hash_api_key(&key);
        let hash2 = hash_api_key(&key);

        // Same key should produce same hash
        assert_eq!(hash1, hash2);
    }
}
