// Ave HTTP Auth System - Crypto Tests
//
// Comprehensive tests for password hashing, API key generation, and cryptographic operations

use ave_http::auth::crypto::{
    generate_api_key, generate_api_key_with_prefix, hash_api_key, hash_password, verify_password,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "MySecurePassword123!";
        let hash = hash_password(password).expect("Should hash password");

        // Verify correct password
        assert!(
            verify_password(password, &hash).expect("Should verify"),
            "Correct password should verify"
        );

        // Verify incorrect password
        assert!(
            !verify_password("WrongPassword", &hash).expect("Should verify"),
            "Wrong password should not verify"
        );
    }

    #[test]
    fn test_password_hash_uniqueness() {
        let password = "SamePassword";
        let hash1 = hash_password(password).expect("Should hash password");
        let hash2 = hash_password(password).expect("Should hash password");

        // Same password should produce different hashes (due to random salt)
        assert_ne!(
            hash1, hash2,
            "Same password should produce different hashes due to random salt"
        );

        // But both should verify
        assert!(verify_password(password, &hash1).expect("Should verify"));
        assert!(verify_password(password, &hash2).expect("Should verify"));
    }

    #[test]
    fn test_password_empty_string() {
        let password = "";
        let hash = hash_password(password).expect("Should hash empty password");
        assert!(
            verify_password(password, &hash).expect("Should verify"),
            "Empty password should verify"
        );
    }

    #[test]
    fn test_password_long_string() {
        let password = "a".repeat(1000);
        let hash = hash_password(&password).expect("Should hash long password");
        assert!(
            verify_password(&password, &hash).expect("Should verify"),
            "Long password should verify"
        );
    }

    #[test]
    fn test_password_unicode_characters() {
        let password = "Password🔐中文العربية";
        let hash = hash_password(password).expect("Should hash unicode password");
        assert!(
            verify_password(password, &hash).expect("Should verify"),
            "Unicode password should verify"
        );
    }

    #[test]
    fn test_password_special_characters() {
        let password = r#"!@#$%^&*()_+-=[]{}|;':",./<>?"#;
        let hash = hash_password(password).expect("Should hash special characters");
        assert!(
            verify_password(password, &hash).expect("Should verify"),
            "Special characters should verify"
        );
    }

    #[test]
    fn test_api_key_generation() {
        let plaintext = generate_api_key();

        // Plaintext should be non-empty
        assert!(!plaintext.is_empty(), "API key should not be empty");

        // Should start with ave_v1_
        assert!(
            plaintext.starts_with("ave_v1_"),
            "API key should have ave_v1_ prefix"
        );

        // Hash it
        let hash = hash_api_key(&plaintext);
        assert!(!hash.is_empty(), "API key hash should not be empty");

        // Plaintext and hash should be different
        assert_ne!(plaintext, hash, "Plaintext and hash should be different");

        // Verify by hashing again
        assert_eq!(
            hash_api_key(&plaintext),
            hash,
            "Same key should produce same hash"
        );
    }

    #[test]
    fn test_api_key_with_prefix() {
        let prefix = "test";
        let plaintext = generate_api_key_with_prefix(prefix);

        // Should start with prefix
        assert!(
            plaintext.starts_with("ave_v1_test_"),
            "API key should start with custom prefix"
        );

        // Should verify
        let hash = hash_api_key(&plaintext);
        assert_eq!(
            hash_api_key(&plaintext),
            hash,
            "Prefixed API key should hash consistently"
        );
    }

    #[test]
    fn test_api_key_uniqueness() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();

        // Different calls should produce different keys
        assert_ne!(key1, key2, "API keys should be unique");
    }

    #[test]
    fn test_api_key_hash_uniqueness() {
        let key = "same_key_for_testing";
        let hash1 = hash_api_key(key);
        let hash2 = hash_api_key(key);

        // Same key should produce same hash (deterministic)
        assert_eq!(
            hash1, hash2,
            "Same API key should produce same hash (SHA-256 is deterministic)"
        );
    }

    #[test]
    fn test_api_key_verification_case_sensitive() {
        let key = "AbCdEfGh123";
        let hash = hash_api_key(key);

        // Correct case should verify
        assert_eq!(
            hash_api_key(key),
            hash,
            "Correct case should verify"
        );

        // Different case should not verify
        assert_ne!(
            hash_api_key("abcdefgh123"),
            hash,
            "Different case should not verify"
        );
    }

    #[test]
    fn test_api_key_empty_string() {
        let key = "";
        let hash = hash_api_key(key);

        // Empty key should still hash and verify
        assert_eq!(hash_api_key(key), hash, "Empty key should hash consistently");
    }

    #[test]
    fn test_api_key_long_prefix() {
        let prefix = "very_long_prefix_for_testing_purposes";
        let plaintext = generate_api_key_with_prefix(prefix);

        assert!(plaintext.starts_with(&format!("ave_v1_{}_", prefix)));
        assert_eq!(
            hash_api_key(&plaintext),
            hash_api_key(&plaintext),
            "Long prefix key should hash consistently"
        );
    }

    #[test]
    fn test_api_key_special_chars_in_prefix() {
        let prefix = "test@123";
        let plaintext = generate_api_key_with_prefix(prefix);

        assert!(plaintext.starts_with("ave_v1_test@123_"));
        assert_eq!(
            hash_api_key(&plaintext),
            hash_api_key(&plaintext),
            "Special char prefix key should hash consistently"
        );
    }

    #[test]
    fn test_api_key_format() {
        let plaintext = generate_api_key();

        // Should be reasonable length (at least 32 chars for security)
        assert!(
            plaintext.len() >= 32,
            "API key should be at least 32 characters"
        );
    }

    #[test]
    fn test_hash_output_format() {
        let password = "TestPassword";
        let hash = hash_password(password).expect("Should hash");

        // Argon2 hash should start with $argon2
        assert!(hash.starts_with("$argon2"), "Hash should be in Argon2 format");
    }

    #[test]
    fn test_api_key_hash_length() {
        let key = "test_key";
        let hash = hash_api_key(key);

        // SHA-256 in hex should be 64 characters
        assert_eq!(hash.len(), 64, "SHA-256 hash should be 64 hex characters");

        // Should be valid hex
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash should be valid hexadecimal"
        );
    }

    #[test]
    fn test_multiple_password_hashing_success() {
        let passwords = vec![
            "Short1",
            "MediumPassword123",
            "VeryLongPasswordWithLotsOfCharacters!@#$%^&*()",
            "🔐🔑",
            "",
        ];

        for password in passwords {
            let hash = hash_password(password).expect("Should hash password");
            assert!(
                verify_password(password, &hash).expect("Should verify"),
                "Password '{}' should verify",
                password
            );
        }
    }

    #[test]
    fn test_multiple_api_key_generation_success() {
        let prefixes = vec!["test", "prod", "dev_v2"];

        for prefix in prefixes {
            let plaintext = generate_api_key_with_prefix(prefix);
            assert_eq!(
                hash_api_key(&plaintext),
                hash_api_key(&plaintext),
                "API key with prefix {:?} should hash consistently",
                prefix
            );
        }
    }
}
