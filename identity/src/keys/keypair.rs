//! Generic key pair wrapper for any DSA implementation

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use std::fmt;

use super::{DSA, DSAlgorithm, Ed25519Signer, PublicKey, SignatureIdentifier};

/// Key pair types supported by the system
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default,
)]
pub enum KeyPairAlgorithm {
    /// Ed25519 elliptic curve signature scheme
    #[default]
    Ed25519,
}

impl From<DSAlgorithm> for KeyPairAlgorithm {
    fn from(algo: DSAlgorithm) -> Self {
        match algo {
            DSAlgorithm::Ed25519 => KeyPairAlgorithm::Ed25519,
        }
    }
}

impl From<KeyPairAlgorithm> for DSAlgorithm {
    fn from(kp_type: KeyPairAlgorithm) -> Self {
        match kp_type {
            KeyPairAlgorithm::Ed25519 => DSAlgorithm::Ed25519,
        }
    }
}

impl KeyPairAlgorithm {
    /// Generate a new key pair for this algorithm
    ///
    /// This is a convenience method that creates a new random key pair
    /// of the specified algorithm type.
    ///
    /// # Example
    /// ```rust
    /// use identity::keys::KeyPairAlgorithm;
    ///
    /// let algorithm = KeyPairAlgorithm::Ed25519;
    /// let keypair = algorithm.generate_keypair().unwrap();
    /// ```
    pub fn generate_keypair(&self) -> Result<KeyPair, CryptoError> {
        KeyPair::generate(*self)
    }
}

impl fmt::Display for KeyPairAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyPairAlgorithm::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

/// Generic key pair wrapper that can hold any DSA implementation
///
/// This provides algorithm-agnostic operations for signing and verification.
///
/// Cloning a KeyPair is cheap because the underlying secret keys are stored
/// in Arc<EncryptedMem>, so only the reference is cloned, not the encrypted data.
///
/// # Example
///
/// ```rust
/// use identity::keys::{KeyPair, KeyPairAlgorithm, DSA};
///
/// // Generate a key pair
/// let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).expect("Failed to generate key pair");
///
/// let message = b"Hello, World!";
///
/// // Sign message using generic interface
/// let signature = keypair.sign(message).unwrap();
///
/// // Get public key
/// let public_key = keypair.public_key();
///
/// // Verify
/// assert!(public_key.verify(message, &signature).is_ok());
/// ```
#[derive(Clone)]
pub enum KeyPair {
    Ed25519(Ed25519Signer),
}

impl KeyPair {
    /// Generate a new random key pair of the specified type
    pub fn generate(key_type: KeyPairAlgorithm) -> Result<Self, CryptoError> {
        match key_type {
            KeyPairAlgorithm::Ed25519 => {
                Ed25519Signer::generate().map(KeyPair::Ed25519)
            }
        }
    }

    /// Create key pair from PKCS#8 DER-encoded secret key
    ///
    /// This method automatically detects the algorithm from the OID in the DER structure.
    /// Supported OIDs:
    /// - Ed25519: 1.3.101.112
    ///
    /// # Errors
    /// - Returns `InvalidDerFormat` if the DER structure is malformed
    /// - Returns `UnsupportedAlgorithm` if the algorithm OID is not supported
    /// - Returns `InvalidSecretKey` if the key data is invalid
    ///
    /// # Example
    /// ```no_run
    /// use identity::keys::KeyPair;
    ///
    /// let der_bytes = std::fs::read("private_key.der").unwrap();
    /// let keypair = KeyPair::from_secret_der(&der_bytes).unwrap();
    /// ```
    pub fn from_secret_der(der: &[u8]) -> Result<Self, CryptoError> {
        use pkcs8::{ObjectIdentifier, PrivateKeyInfo};

        // Parse the DER structure
        let private_key_info = PrivateKeyInfo::try_from(der)
            .map_err(|e| CryptoError::InvalidDerFormat(e.to_string()))?;

        // Get the algorithm OID
        let oid = private_key_info.algorithm.oid;

        // Ed25519 OID: 1.3.101.112
        const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

        // Match OID to algorithm
        if oid == ED25519_OID {
            // Extract the secret key bytes from the OCTET STRING
            let secret_key = private_key_info.private_key;

            // Ed25519 keys in PKCS#8 are wrapped in an OCTET STRING
            // The first byte should be 0x04 (OCTET STRING tag), followed by length
            if secret_key.len() < 2 || secret_key[0] != 0x04 {
                return Err(CryptoError::InvalidSecretKey(
                    "Invalid Ed25519 key encoding in DER".to_string(),
                ));
            }

            let key_length = secret_key[1] as usize;
            if secret_key.len() < 2 + key_length {
                return Err(CryptoError::InvalidSecretKey(
                    "Truncated Ed25519 key in DER".to_string(),
                ));
            }

            let actual_key = &secret_key[2..2 + key_length];
            Ed25519Signer::from_secret_key(actual_key).map(KeyPair::Ed25519)
        } else {
            Err(CryptoError::UnsupportedAlgorithm(format!(
                "Algorithm with OID {} is not supported",
                oid
            )))
        }
    }

    /// Create key pair from seed
    pub fn from_seed(
        key_type: KeyPairAlgorithm,
        seed: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        match key_type {
            KeyPairAlgorithm::Ed25519 => {
                Ed25519Signer::from_seed(seed).map(KeyPair::Ed25519)
            }
        }
    }

    /// Derive key pair from arbitrary data (will be hashed)
    pub fn derive_from_data(
        key_type: KeyPairAlgorithm,
        data: &[u8],
    ) -> Result<Self, CryptoError> {
        match key_type {
            KeyPairAlgorithm::Ed25519 => {
                Ed25519Signer::derive_from_data(data).map(KeyPair::Ed25519)
            }
        }
    }

    /// Create key pair from secret key bytes
    ///
    /// Attempts to auto-detect the algorithm from key length.
    /// For explicit algorithm selection, use `from_secret_key_with_type`.
    pub fn from_secret_key(secret_key: &[u8]) -> Result<Self, CryptoError> {
        // Try to detect algorithm from key length
        match secret_key.len() {
            32 | 64 => {
                Ed25519Signer::from_secret_key(secret_key).map(KeyPair::Ed25519)
            }
            _ => Err(CryptoError::InvalidSecretKey(format!(
                "Unsupported key length: {} bytes",
                secret_key.len()
            ))),
        }
    }

    /// Create key pair from secret key bytes with explicit type
    pub fn from_secret_key_with_type(
        key_type: KeyPairAlgorithm,
        secret_key: &[u8],
    ) -> Result<Self, CryptoError> {
        match key_type {
            KeyPairAlgorithm::Ed25519 => {
                Ed25519Signer::from_secret_key(secret_key).map(KeyPair::Ed25519)
            }
        }
    }

    /// Get the key pair type
    #[inline]
    pub fn key_type(&self) -> KeyPairAlgorithm {
        match self {
            KeyPair::Ed25519(_) => KeyPairAlgorithm::Ed25519,
        }
    }

    /// Sign a message using the appropriate algorithm
    #[inline]
    pub fn sign(
        &self,
        message: &[u8],
    ) -> Result<SignatureIdentifier, CryptoError> {
        match self {
            KeyPair::Ed25519(signer) => signer.sign(message),
        }
    }

    /// Get the algorithm used by this key pair
    #[inline]
    pub fn algorithm(&self) -> DSAlgorithm {
        match self {
            KeyPair::Ed25519(signer) => signer.algorithm(),
        }
    }

    /// Get the algorithm identifier
    #[inline]
    pub fn algorithm_id(&self) -> u8 {
        match self {
            KeyPair::Ed25519(signer) => signer.algorithm_id(),
        }
    }

    /// Get the public key bytes
    #[inline]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            KeyPair::Ed25519(signer) => signer.public_key_bytes(),
        }
    }

    /// Get the public key as a PublicKey wrapper
    #[inline]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self.algorithm(), self.public_key_bytes())
            .expect("KeyPair should always have valid public key")
    }

    /// Get the secret key bytes (if available)
    #[inline]
    pub fn secret_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        match self {
            KeyPair::Ed25519(signer) => signer.secret_key_bytes(),
        }
    }

    /// Serialize to bytes (includes algorithm identifier and secret key)
    ///
    /// # Warning
    /// This exposes the secret key. Use with extreme caution.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let secret = self.secret_key_bytes()?;
        let mut result = Vec::with_capacity(1 + secret.len());
        result.push(self.algorithm_id());
        result.extend_from_slice(&secret);
        Ok(result)
    }

    /// Deserialize from bytes (includes algorithm identifier)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidSecretKey(
                "Data too short to contain algorithm identifier".to_string(),
            ));
        }

        let id = bytes[0];
        let algorithm = DSAlgorithm::from_identifier(id)?;
        let key_type = KeyPairAlgorithm::from(algorithm);
        let secret_key = &bytes[1..];

        Self::from_secret_key_with_type(key_type, secret_key)
    }

    /// Serialize to PKCS#8 DER format
    ///
    /// This creates a DER-encoded PKCS#8 PrivateKeyInfo structure containing
    /// the secret key and algorithm identifier.
    ///
    /// # Errors
    /// - Returns `InvalidSecretKey` if the secret key cannot be retrieved
    ///
    /// # Example
    /// ```no_run
    /// use identity::keys::{KeyPair, KeyPairAlgorithm};
    ///
    /// let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
    /// let der_bytes = keypair.to_secret_der().unwrap();
    /// std::fs::write("private_key.der", der_bytes).unwrap();
    /// ```
    pub fn to_secret_der(&self) -> Result<Vec<u8>, CryptoError> {
        use pkcs8::{der::Encode, ObjectIdentifier, PrivateKeyInfo};

        const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

        let secret_key_bytes = self.secret_key_bytes()?;

        // Wrap the key in an OCTET STRING (0x04 tag)
        let mut wrapped_key = Vec::with_capacity(2 + secret_key_bytes.len());
        wrapped_key.push(0x04); // OCTET STRING tag
        wrapped_key.push(secret_key_bytes.len() as u8); // length
        wrapped_key.extend_from_slice(&secret_key_bytes);

        let algorithm_identifier = pkcs8::AlgorithmIdentifierRef {
            oid: ED25519_OID,
            parameters: None,
        };

        let private_key_info = PrivateKeyInfo {
            algorithm: algorithm_identifier,
            private_key: &wrapped_key,
            public_key: None,
        };

        private_key_info
            .to_der()
            .map_err(|e| CryptoError::InvalidSecretKey(format!("DER encoding failed: {}", e)))
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        KeyPair::Ed25519(Ed25519Signer::default())
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::common::base64_encoding;
        f.debug_struct("KeyPair")
            .field("type", &self.key_type())
            .field("algorithm", &self.algorithm())
            .field(
                "public_key",
                &base64_encoding::encode(&self.public_key_bytes()),
            )
            .finish_non_exhaustive()
    }
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} KeyPair", self.key_type())
    }
}

// Implement DSA trait for KeyPair to make it fully interchangeable
impl DSA for KeyPair {
    #[inline]
    fn algorithm_id(&self) -> u8 {
        KeyPair::algorithm_id(self)
    }

    #[inline]
    fn signature_length(&self) -> usize {
        match self {
            KeyPair::Ed25519(signer) => signer.signature_length(),
        }
    }

    #[inline]
    fn sign(&self, message: &[u8]) -> Result<SignatureIdentifier, CryptoError> {
        KeyPair::sign(self, message)
    }

    #[inline]
    fn algorithm(&self) -> DSAlgorithm {
        KeyPair::algorithm(self)
    }

    #[inline]
    fn public_key_bytes(&self) -> Vec<u8> {
        KeyPair::public_key_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generate() {
        let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
        assert_eq!(keypair.algorithm(), DSAlgorithm::Ed25519);
        assert_eq!(keypair.key_type(), KeyPairAlgorithm::Ed25519);
        assert_eq!(keypair.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_keypair_sign_verify() {
        let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
        let message = b"Test message";

        let signature = keypair.sign(message).unwrap();
        let public_key = keypair.public_key();

        assert!(public_key.verify(message, &signature).is_ok());
        assert!(public_key.verify(b"Wrong message", &signature).is_err());
    }

    #[test]
    fn test_keypair_from_seed() {
        let seed = [42u8; 32];
        let keypair1 =
            KeyPair::from_seed(KeyPairAlgorithm::Ed25519, &seed).unwrap();
        let keypair2 =
            KeyPair::from_seed(KeyPairAlgorithm::Ed25519, &seed).unwrap();

        // Same seed should produce same keys
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_keypair_derive_from_data() {
        let data = b"my passphrase";
        let keypair1 =
            KeyPair::derive_from_data(KeyPairAlgorithm::Ed25519, data).unwrap();
        let keypair2 =
            KeyPair::derive_from_data(KeyPairAlgorithm::Ed25519, data).unwrap();

        // Same data should produce same keys
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());

        // Different data should produce different keys
        let keypair3 =
            KeyPair::derive_from_data(KeyPairAlgorithm::Ed25519, b"different")
                .unwrap();
        assert_ne!(keypair1.public_key_bytes(), keypair3.public_key_bytes());
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
        let message = b"Test message";

        // Serialize
        let bytes = keypair.to_bytes().unwrap();
        assert_eq!(bytes[0], b'E'); // Ed25519 identifier

        // Deserialize
        let keypair2 = KeyPair::from_bytes(&bytes).unwrap();

        // Should produce same signatures
        let sig1 = keypair.sign(message).unwrap();
        let sig2 = keypair2.sign(message).unwrap();

        // Both should verify correctly
        let public_key = keypair.public_key();
        assert!(public_key.verify(message, &sig1).is_ok());
        assert!(public_key.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_keypair_dsa_trait() {
        let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
        let message = b"Test message";

        // Use DSA trait methods
        let signature = DSA::sign(&keypair, message).unwrap();
        assert_eq!(DSA::algorithm(&keypair), DSAlgorithm::Ed25519);
        assert_eq!(DSA::algorithm_id(&keypair), b'E');

        // Verify
        let public_key = keypair.public_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_keypair_public_key_wrapper() {
        let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
        let public_key = keypair.public_key();

        assert_eq!(public_key.algorithm(), keypair.algorithm());
        assert_eq!(public_key.as_bytes(), &keypair.public_key_bytes()[..]);
    }

    #[test]
    fn test_keypair_from_secret_key_autodetect() {
        let keypair1 = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
        let secret_bytes = keypair1.secret_key_bytes().unwrap();

        // Auto-detect should work
        let keypair2 = KeyPair::from_secret_key(&secret_bytes).unwrap();

        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_keypair_type_conversion() {
        let kp_type = KeyPairAlgorithm::Ed25519;
        let algo: DSAlgorithm = kp_type.into();
        assert_eq!(algo, DSAlgorithm::Ed25519);

        let kp_type2: KeyPairAlgorithm = algo.into();
        assert_eq!(kp_type, kp_type2);
    }

    #[test]
    fn test_keypair_algorithm_generate() {
        let algorithm = KeyPairAlgorithm::Ed25519;
        let keypair = algorithm.generate_keypair().unwrap();

        assert_eq!(keypair.key_type(), KeyPairAlgorithm::Ed25519);
        assert_eq!(keypair.algorithm(), DSAlgorithm::Ed25519);

        // Should be able to sign
        let message = b"test";
        let signature = keypair.sign(message).unwrap();
        let public_key = keypair.public_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_keypair_algorithm_display() {
        let algorithm = KeyPairAlgorithm::Ed25519;
        assert_eq!(algorithm.to_string(), "Ed25519");
    }

    #[test]
    fn test_default_keypair() {
        let keypair = KeyPair::default();
        assert_eq!(keypair.key_type(), KeyPairAlgorithm::Ed25519);
    }

    #[test]
    fn test_keypair_clone() {
        // Test that cloning works correctly
        let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
        let keypair_clone = keypair.clone();

        // Both should have the same public key
        assert_eq!(
            keypair.public_key_bytes(),
            keypair_clone.public_key_bytes()
        );

        // Both should sign the same way
        let message = b"test message";
        let sig1 = keypair.sign(message).unwrap();
        let sig2 = keypair_clone.sign(message).unwrap();

        // Signatures should be identical (deterministic)
        assert_eq!(sig1, sig2);

        // Both signatures should verify
        let public_key = keypair.public_key();
        assert!(public_key.verify(message, &sig1).is_ok());
        assert!(public_key.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_keypair_der_roundtrip() {
        // Test DER serialization and deserialization
        let keypair1 = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
        let message = b"Test message for DER roundtrip";

        // Serialize to DER
        let der_bytes = keypair1.to_secret_der().unwrap();

        // Verify it starts with DER SEQUENCE tag
        assert_eq!(der_bytes[0], 0x30); // SEQUENCE tag

        // Deserialize from DER
        let keypair2 = KeyPair::from_secret_der(&der_bytes).unwrap();

        // Should have the same public key
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());

        // Should produce verifiable signatures
        let sig1 = keypair1.sign(message).unwrap();
        let sig2 = keypair2.sign(message).unwrap();

        let public_key = keypair1.public_key();
        assert!(public_key.verify(message, &sig1).is_ok());
        assert!(public_key.verify(message, &sig2).is_ok());
    }

    #[test]
    fn test_keypair_from_der_invalid() {
        // Test error handling for invalid DER data
        let invalid_der = vec![0x00, 0x01, 0x02];
        let result = KeyPair::from_secret_der(&invalid_der);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidDerFormat(_)));
    }

    #[test]
    fn test_keypair_from_der_unsupported_algorithm() {
        // Create a valid DER structure but with an unsupported OID
        use pkcs8::{der::Encode, ObjectIdentifier, PrivateKeyInfo};

        // Use a different OID (e.g., secp256k1: 1.3.132.0.10)
        let unsupported_oid = ObjectIdentifier::new_unwrap("1.3.132.0.10");

        let fake_key = vec![0x04, 0x20]; // OCTET STRING tag + length
        let fake_key = [&fake_key[..], &[0u8; 32]].concat();

        let algorithm_identifier = pkcs8::AlgorithmIdentifierRef {
            oid: unsupported_oid,
            parameters: None,
        };

        let private_key_info = PrivateKeyInfo {
            algorithm: algorithm_identifier,
            private_key: &fake_key,
            public_key: None,
        };

        let der_bytes = private_key_info.to_der().unwrap();

        let result = KeyPair::from_secret_der(&der_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::UnsupportedAlgorithm(_)));
    }
}
