//! Ed25519 signature implementation with encrypted secret key storage

use crate::error::CryptoError;
use ed25519_dalek::{Signer as Ed25519SignerTrait, SigningKey, VerifyingKey};
use memsecurity::EncryptedMem;
use std::{fmt, sync::Arc};
use zeroize::Zeroize;

use super::{DSA, DSAlgorithm, SignatureIdentifier};

/// 1-byte identifier for Ed25519 signature algorithm: 'E'
pub const ED25519_ID: u8 = b'E';

/// Ed25519 public key length in bytes
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Ed25519 secret key length in bytes
pub const ED25519_SECRET_KEY_LENGTH: usize = 32;

/// Ed25519 signature length in bytes
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Ed25519 signer implementation with encrypted secret key storage
///
/// The secret key is stored encrypted in memory using the `memsecurity` crate,
/// which provides encryption, automatic zeroization, and memory locking (mlock)
/// for enhanced security.
///
/// The secret key is wrapped in an `Arc`, making cloning cheap and safe.
/// Cloning only clones the reference, not the encrypted data, and the secret
/// key is immutable after creation.
#[derive(Default, Clone)]
pub struct Ed25519Signer {
    /// Public verifying key
    public_key: VerifyingKey,
    /// Encrypted secret key (None for verification-only instances)
    /// Wrapped in Arc to allow cheap cloning without duplicating sensitive data
    secret_key: Option<Arc<EncryptedMem>>,
}

impl Ed25519Signer {
    /// Decrypt the secret key from encrypted memory
    fn decrypt_secret_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        match &self.secret_key {
            Some(encrypted) => {
                let bytes = encrypted.decrypt().map_err(|e| {
                    CryptoError::InvalidSecretKey(format!(
                        "Failed to decrypt secret key: {:?}",
                        e
                    ))
                })?;
                Ok(Vec::from(bytes.as_ref()))
            }
            None => Err(CryptoError::MissingSecretKey),
        }
    }

    /// Create an encrypted EncryptedMem from secret key bytes
    /// This is only called during construction, ensuring immutability
    fn create_encrypted_secret(
        secret_key: &[u8],
    ) -> Result<Arc<EncryptedMem>, CryptoError> {
        let mut encrypted = EncryptedMem::new();
        encrypted.encrypt(&secret_key.to_vec()).map_err(|e| {
            CryptoError::InvalidSecretKey(format!(
                "Failed to encrypt secret key: {:?}",
                e
            ))
        })?;
        Ok(Arc::new(encrypted))
    }

    /// Generate a new random Ed25519 key pair
    ///
    /// # Errors
    /// Returns an error if the system's random number generator is unavailable
    /// or fails to provide sufficient entropy.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| {
            CryptoError::InvalidSecretKey(format!(
                "Failed to generate random seed: {}",
                e
            ))
        })?;
        Self::from_seed(&seed)
    }

    /// Derive keys from arbitrary data (will be hashed to 32 bytes)
    ///
    /// This method accepts data of any length and uses Blake3 to derive
    /// a deterministic 32-byte seed for Ed25519 key generation.
    ///
    /// **Important**: This function ALWAYS hashes the input, even if you provide
    /// exactly 32 bytes. This means:
    /// - `derive_from_data(&[x; 32])` will produce DIFFERENT keys than `from_seed(&[x; 32])`
    /// - Use this for arbitrary-length data, passphrases, or when you want deterministic hashing
    /// - Use `from_seed()` when you already have a properly-sized 32-byte seed
    ///   that should be used directly without additional hashing
    ///
    /// # Errors
    /// Returns an error if the data is empty or if the secret key encryption fails.
    ///
    /// # Example
    /// ```
    /// use identity::keys::Ed25519Signer;
    ///
    /// // Derive from a passphrase
    /// let signer = Ed25519Signer::derive_from_data(b"my secure passphrase").unwrap();
    /// ```
    pub fn derive_from_data(data: &[u8]) -> Result<Self, CryptoError> {
        // Reject empty data
        if data.is_empty() {
            return Err(CryptoError::InvalidSecretKey(
                "Cannot derive keys from empty data. Use generate() for random keys.".to_string(),
            ));
        }

        use crate::hash::{Blake3Hasher, Hash as HashTrait};

        // Hash the data to get exactly 32 bytes
        let hasher = Blake3Hasher;
        let hash = hasher.hash(data);
        let seed_bytes = hash.hash_bytes();

        let key_array: [u8; 32] = seed_bytes
            .try_into()
            .expect("Blake3 always produces 32 bytes");

        Self::from_seed(&key_array)
    }

    /// Create from a seed of exactly 32 bytes (no hashing)
    ///
    /// Use this when you already have a properly-sized 32-byte seed that should
    /// be used directly as the Ed25519 secret key WITHOUT additional hashing.
    ///
    /// **Important**: This function does NOT hash the input. If you want deterministic
    /// key derivation from arbitrary data or passphrases, use `derive_from_data()` instead.
    ///
    /// # Errors
    /// Returns an error if the secret key encryption fails.
    ///
    /// # Example
    /// ```
    /// use identity::keys::Ed25519Signer;
    ///
    /// let seed = [42u8; 32];
    /// let signer = Ed25519Signer::from_seed(&seed).unwrap();
    /// ```
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        // Seed length is guaranteed by type system (&[u8; 32])
        let signing_key = SigningKey::from_bytes(seed);
        let public_key = signing_key.verifying_key();

        // Encrypt the secret key (immutable after creation)
        let encrypted_secret = Self::create_encrypted_secret(seed)?;

        Ok(Self {
            public_key,
            secret_key: Some(encrypted_secret),
        })
    }

    /// Create from secret key bytes (32 bytes)
    ///
    /// # Errors
    /// Returns an error if the key length is invalid or encryption fails.
    pub fn from_secret_key(secret_key: &[u8]) -> Result<Self, CryptoError> {
        let key_bytes: [u8; 32] = secret_key.try_into().map_err(|_| {
            CryptoError::InvalidSecretKey(format!(
                "Invalid secret key length: expected {} bytes, got {}",
                ED25519_SECRET_KEY_LENGTH,
                secret_key.len()
            ))
        })?;
        Self::from_seed(&key_bytes)
    }

    /// Create a verification-only instance from a public key
    ///
    /// This creates an Ed25519Signer that can only verify signatures, not create them.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, CryptoError> {
        if public_key.len() != ED25519_PUBLIC_KEY_LENGTH {
            return Err(CryptoError::InvalidPublicKey(format!(
                "Invalid public key length: expected {} bytes, got {}",
                ED25519_PUBLIC_KEY_LENGTH,
                public_key.len()
            )));
        }

        let key_bytes: [u8; 32] = public_key.try_into().map_err(|_| {
            CryptoError::InvalidPublicKey("Invalid length".to_string())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        Ok(Self {
            public_key: verifying_key,
            secret_key: None,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> VerifyingKey {
        self.public_key
    }

    /// Get the secret key bytes (decrypts from secure storage)
    ///
    /// # Errors
    /// Returns an error if no secret key is available or decryption fails.
    pub fn secret_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_secret_bytes()
    }
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::common::base64_encoding;
        f.debug_struct("Ed25519Signer")
            .field(
                "public_key",
                &base64_encoding::encode(self.public_key().as_bytes()),
            )
            .finish_non_exhaustive()
    }
}

impl DSA for Ed25519Signer {
    fn algorithm_id(&self) -> u8 {
        ED25519_ID
    }

    fn signature_length(&self) -> usize {
        ED25519_SIGNATURE_LENGTH
    }

    fn sign(&self, message: &[u8]) -> Result<SignatureIdentifier, CryptoError> {
        // Decrypt the secret key from secure storage
        let mut secret_bytes = self.decrypt_secret_bytes()?;

        // Create signing key from decrypted bytes
        // Note: Length was already validated during key creation, so we can safely unwrap
        let key_array: [u8; 32] = secret_bytes
            .as_slice()
            .try_into()
            .expect("Secret key should always be 32 bytes");
        let signing_key = SigningKey::from_bytes(&key_array);

        // Sign the message
        let signature = signing_key.sign(message);
        let signature_bytes = signature.to_bytes();

        // Explicitly zeroize the secret bytes before dropping
        secret_bytes.zeroize();

        // Ed25519 always produces 64-byte signatures
        SignatureIdentifier::new(DSAlgorithm::Ed25519, signature_bytes.to_vec())
    }

    fn algorithm(&self) -> DSAlgorithm {
        DSAlgorithm::Ed25519
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Hello, World!";

        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.algorithm(), DSAlgorithm::Ed25519);

        let public_key = signer.public_key();
        assert!(signature.verify(message, public_key.as_bytes()).is_ok());
    }

    #[test]
    fn test_derive_from_data() {
        // Test with arbitrary-length data (will be hashed)
        let short_data = b"hello";
        let signer1 = Ed25519Signer::derive_from_data(short_data).unwrap();
        let signer2 = Ed25519Signer::derive_from_data(short_data).unwrap();

        // Same data should produce same keys
        assert_eq!(signer1.public_key_bytes(), signer2.public_key_bytes());

        // Different data should produce different keys
        let different_data = b"world";
        let signer3 = Ed25519Signer::derive_from_data(different_data).unwrap();
        assert_ne!(signer1.public_key_bytes(), signer3.public_key_bytes());

        // Long data should also work
        let long_data =
            b"this is a very long passphrase that is much longer than 32 bytes";
        let signer4 = Ed25519Signer::derive_from_data(long_data).unwrap();
        assert_ne!(signer1.public_key_bytes(), signer4.public_key_bytes());

        // Empty data should return an error
        let empty_data = b"";
        let result = Ed25519Signer::derive_from_data(empty_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_seed() {
        // Test with exact 32-byte seeds (no hashing)
        let seed = [42u8; 32];
        let signer1 = Ed25519Signer::from_seed(&seed).unwrap();
        let signer2 = Ed25519Signer::from_seed(&seed).unwrap();

        // Same seed should produce same keys
        assert_eq!(signer1.public_key_bytes(), signer2.public_key_bytes());

        // derive_from_data with 32 bytes should produce DIFFERENT keys than from_seed
        // because derive_from_data hashes the input
        let signer3 = Ed25519Signer::derive_from_data(&seed).unwrap();
        assert_ne!(signer1.public_key_bytes(), signer3.public_key_bytes());
    }

    #[test]
    fn test_from_public_key() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Test message";

        // Sign with full signer
        let signature = signer.sign(message).unwrap();

        // Create verification-only signer from public key
        let verifier =
            Ed25519Signer::from_public_key(&signer.public_key_bytes()).unwrap();

        // Should be able to get public key
        assert_eq!(verifier.public_key_bytes(), signer.public_key_bytes());

        // Should not be able to sign (no secret key)
        assert!(verifier.sign(message).is_err());

        // But verification should still work
        assert!(
            signature
                .verify(message, verifier.public_key().as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn test_encrypted_secret_key() {
        let seed = [42u8; 32];
        let signer = Ed25519Signer::from_seed(&seed).unwrap();

        // Should be able to get secret key bytes (will decrypt)
        let secret = signer.secret_key_bytes().unwrap();
        assert_eq!(secret.len(), 32);

        // Create new signer from same seed
        let signer2 = Ed25519Signer::from_seed(&seed).unwrap();
        let secret2 = signer2.secret_key_bytes().unwrap();

        // Should have same secret key
        assert_eq!(secret, secret2);
    }

    #[test]
    fn test_invalid_key_lengths() {
        // Test invalid secret key length
        let invalid_secret = vec![0u8; 16]; // Only 16 bytes instead of 32
        let result = Ed25519Signer::from_secret_key(&invalid_secret);
        assert!(result.is_err());

        // Test invalid public key length
        let invalid_public = vec![0u8; 16]; // Only 16 bytes instead of 32
        let result = Ed25519Signer::from_public_key(&invalid_public);
        assert!(result.is_err());
    }

    #[test]
    fn test_concurrent_signing() {
        use std::sync::Arc;
        use std::thread;

        // Create a signer
        let signer = Arc::new(Ed25519Signer::generate().unwrap());

        // Spawn multiple threads that sign concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let signer_clone = Arc::clone(&signer);
            let msg = format!("message {}", i);

            let handle = thread::spawn(move || {
                let signature = signer_clone.sign(msg.as_bytes()).unwrap();
                // Verify the signature is valid
                let public_key = signer_clone.public_key();
                assert!(
                    signature
                        .verify(msg.as_bytes(), public_key.as_bytes())
                        .is_ok()
                );
                signature
            });
            handles.push(handle);
        }

        // Collect all results
        let signatures: Vec<_> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All signatures should be valid
        assert_eq!(signatures.len(), 10);

        // Each signature should be different (different messages)
        for i in 0..signatures.len() {
            for j in i + 1..signatures.len() {
                assert_ne!(
                    signatures[i], signatures[j],
                    "Signatures for different messages should be different"
                );
            }
        }
    }

    #[test]
    fn test_send_sync_traits() {
        // This test verifies that Ed25519Signer implements Send + Sync
        // which is required for thread safety
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Ed25519Signer>();
        assert_sync::<Ed25519Signer>();
    }

    #[test]
    fn test_concurrent_key_generation() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        // Generate keys concurrently from multiple threads
        for _ in 0..5 {
            let counter_clone = Arc::clone(&counter);

            let handle = thread::spawn(move || {
                let signer = Ed25519Signer::generate().unwrap();

                // Test that the key works
                let message = b"test";
                let signature = signer.sign(message).unwrap();
                let public_key = signer.public_key();
                assert!(
                    signature.verify(message, public_key.as_bytes()).is_ok()
                );

                counter_clone.fetch_add(1, Ordering::SeqCst);
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_clone_shares_arc() {
        // Test that cloning shares the Arc, not duplicating encrypted data
        let signer = Ed25519Signer::generate().unwrap();
        let signer_clone = signer.clone();

        // Both should have the same public key
        assert_eq!(signer.public_key_bytes(), signer_clone.public_key_bytes());

        // Both should be able to sign
        let message = b"test message";
        let sig1 = signer.sign(message).unwrap();
        let sig2 = signer_clone.sign(message).unwrap();

        // Signatures should be identical (same key, same message, deterministic)
        assert_eq!(sig1, sig2);

        // Verify Arc is shared (strong count should be 2)
        if let Some(ref secret) = signer.secret_key {
            assert_eq!(Arc::strong_count(secret), 2);
        }
    }

    #[test]
    fn test_clone_verification_only() {
        // Test cloning a verification-only instance (no secret key)
        let full_signer = Ed25519Signer::generate().unwrap();
        let verifier =
            Ed25519Signer::from_public_key(&full_signer.public_key_bytes())
                .unwrap();

        // Clone the verification-only instance
        let verifier_clone = verifier.clone();

        // Both should have the same public key
        assert_eq!(
            verifier.public_key_bytes(),
            verifier_clone.public_key_bytes()
        );

        // Neither should be able to sign
        let message = b"test";
        assert!(verifier.sign(message).is_err());
        assert!(verifier_clone.sign(message).is_err());

        // Both should have None for secret_key
        assert!(verifier.secret_key.is_none());
        assert!(verifier_clone.secret_key.is_none());
    }
}
