//! Integration tests for the identity crate
//!
//! These tests verify complete workflows that span multiple modules.

use borsh::{BorshDeserialize, BorshSerialize};
use ave_identity::{
    BLAKE3_HASHER,
    error::CryptoError,
    hash::DigestIdentifier,
    hash_borsh,
    keys::{KeyPair, KeyPairAlgorithm, PublicKey},
    signature::Signature,
};

/// Test data structure for serialization
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
struct TestDocument {
    title: String,
    content: String,
    version: u32,
}

#[test]
fn test_complete_signing_workflow() {
    // 1. Generate keypair
    let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519)
        .expect("Failed to generate keypair");

    // 2. Create a document
    let document = TestDocument {
        title: "Test Document".to_string(),
        content: "This is a test document".to_string(),
        version: 1,
    };

    // 3. Sign the document
    let signature = Signature::new(&document, &keypair)
        .expect("Failed to create signature");

    // 4. Verify the signature
    signature
        .verify(&document)
        .expect("Signature verification failed");

    // 5. Export public key
    let public_key = keypair.public_key();
    let pub_key_str = public_key.to_string();

    // 6. Parse public key from string
    let parsed_public_key: PublicKey = pub_key_str.parse()
        .expect("Failed to parse public key");

    assert_eq!(public_key, parsed_public_key);

    // 7. Verify signature using parsed public key
    assert_eq!(signature.signer, parsed_public_key);
}

#[test]
fn test_hash_serialize_deserialize_verify() {
    // 1. Create test data
    let data = TestDocument {
        title: "Hash Test".to_string(),
        content: "Testing hash workflow".to_string(),
        version: 2,
    };

    // 2. Hash the data
    let hash1 = hash_borsh(&BLAKE3_HASHER, &data).expect("Failed to hash data");

    // 3. Serialize hash to string
    let hash_str = hash1.to_string();

    // 4. Deserialize hash from string
    let hash2: DigestIdentifier = hash_str.parse()
        .expect("Failed to parse hash");

    // 5. Verify hashes match
    assert_eq!(hash1, hash2);

    // 6. Verify hash against original data
    assert!(hash1.verify(&borsh::to_vec(&data).unwrap()));

    // 7. Verify hash fails for different data
    let different_data = TestDocument {
        title: "Different".to_string(),
        content: "Different content".to_string(),
        version: 3,
    };
    assert!(!hash1.verify(&borsh::to_vec(&different_data).unwrap()));
}

#[test]
fn test_deterministic_key_derivation() {
    // 1. Derive keys from passphrase
    let passphrase = b"my secure passphrase for testing";

    let keypair1 =
        KeyPair::derive_from_data(KeyPairAlgorithm::Ed25519, passphrase)
            .expect("Failed to derive keypair");

    let keypair2 =
        KeyPair::derive_from_data(KeyPairAlgorithm::Ed25519, passphrase)
            .expect("Failed to derive keypair");

    // 2. Verify keys are identical
    assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());

    // 3. Sign with first keypair
    let message = b"test message";
    let signature = keypair1.sign(message).expect("Failed to sign");

    // 4. Verify with second keypair's public key
    let public_key2 = keypair2.public_key();
    assert!(public_key2.verify(message, &signature).is_ok());
}

#[test]
fn test_signature_tamper_detection() {
    // 1. Generate keypair and sign document
    let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();

    let document = TestDocument {
        title: "Original".to_string(),
        content: "Original content".to_string(),
        version: 1,
    };

    let signature = Signature::new(&document, &keypair).unwrap();

    // 2. Verify original signature
    assert!(signature.verify(&document).is_ok());

    // 3. Create tampered document
    let tampered_document = TestDocument {
        title: "Original".to_string(),
        content: "Modified content".to_string(), // Changed!
        version: 1,
    };

    // 4. Verification should fail for tampered document
    assert!(signature.verify(&tampered_document).is_err());
}

#[test]
fn test_cross_keypair_verification_failure() {
    // 1. Generate two different keypairs
    let keypair1 = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
    let keypair2 = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();

    // 2. Sign with keypair1
    let message = b"test message";
    let signature1 = keypair1.sign(message).unwrap();

    // 3. Try to verify with keypair2's public key (should fail)
    let public_key2 = keypair2.public_key();
    assert!(public_key2.verify(message, &signature1).is_err());

    // 4. Verify with correct public key (should succeed)
    let public_key1 = keypair1.public_key();
    assert!(public_key1.verify(message, &signature1).is_ok());
}

#[test]
fn test_serialization_roundtrip() {
    let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();

    let document = TestDocument {
        title: "Serialization Test".to_string(),
        content: "Testing full serialization".to_string(),
        version: 1,
    };

    // 1. Create signature
    let signature = Signature::new(&document, &keypair).unwrap();

    // 2. Serialize signature to JSON
    let json = serde_json::to_string(&signature)
        .expect("Failed to serialize signature");

    // 3. Deserialize signature from JSON
    let deserialized_signature: Signature =
        serde_json::from_str(&json).expect("Failed to deserialize signature");

    // 4. Verify deserialized signature
    assert_eq!(signature, deserialized_signature);
    assert!(deserialized_signature.verify(&document).is_ok());

    // 5. Test Borsh serialization
    let borsh_bytes =
        borsh::to_vec(&signature).expect("Failed to serialize with Borsh");

    let borsh_deserialized: Signature = borsh::from_slice(&borsh_bytes)
        .expect("Failed to deserialize with Borsh");

    assert_eq!(signature, borsh_deserialized);
    assert!(borsh_deserialized.verify(&document).is_ok());
}

#[test]
fn test_multiple_signatures_same_document() {
    // Multiple parties signing the same document
    let keypair1 = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
    let keypair2 = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
    let keypair3 = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();

    let document = TestDocument {
        title: "Multi-signature Document".to_string(),
        content: "This document is signed by multiple parties".to_string(),
        version: 1,
    };

    // Create signatures from all three keypairs
    let sig1 = Signature::new(&document, &keypair1).unwrap();
    let sig2 = Signature::new(&document, &keypair2).unwrap();
    let sig3 = Signature::new(&document, &keypair3).unwrap();

    // All signatures should verify
    assert!(sig1.verify(&document).is_ok());
    assert!(sig2.verify(&document).is_ok());
    assert!(sig3.verify(&document).is_ok());

    // All signatures should be different
    assert_ne!(sig1, sig2);
    assert_ne!(sig2, sig3);
    assert_ne!(sig1, sig3);

    // Each signature has a different signer
    assert_ne!(sig1.signer, sig2.signer);
    assert_ne!(sig2.signer, sig3.signer);
    assert_ne!(sig1.signer, sig3.signer);
}

#[test]
fn test_hash_collision_resistance() {
    // Create multiple similar documents and verify they hash differently
    let doc1 = TestDocument {
        title: "Document 1".to_string(),
        content: "Content".to_string(),
        version: 1,
    };

    let doc2 = TestDocument {
        title: "Document 2".to_string(), // Different title
        content: "Content".to_string(),
        version: 1,
    };

    let doc3 = TestDocument {
        title: "Document 1".to_string(),
        content: "Different Content".to_string(), // Different content
        version: 1,
    };

    let hash1 = hash_borsh(&BLAKE3_HASHER, &doc1).unwrap();
    let hash2 = hash_borsh(&BLAKE3_HASHER, &doc2).unwrap();
    let hash3 = hash_borsh(&BLAKE3_HASHER, &doc3).unwrap();

    // All hashes should be different
    assert_ne!(hash1, hash2);
    assert_ne!(hash2, hash3);
    assert_ne!(hash1, hash3);
}

#[test]
fn test_error_handling_invalid_encoding() {
    // Test invalid algorithm identifier for public key
    let invalid_str = "This is not valid!@#$";
    let result: Result<PublicKey, _> = invalid_str.parse();
    assert!(matches!(result, Err(CryptoError::UnknownAlgorithm(_))));

    // Test invalid algorithm identifier for hash
    let result: Result<DigestIdentifier, _> = invalid_str.parse();
    assert!(matches!(result, Err(CryptoError::UnknownAlgorithm(_))));

    // Test invalid base64 after valid algorithm identifier
    let invalid_base64 = "E!!!invalid!!!";
    let result: Result<PublicKey, _> = invalid_base64.parse();
    assert!(matches!(result, Err(CryptoError::Base64DecodeError(_))));

    let invalid_base64 = "B!!!invalid!!!";
    let result: Result<DigestIdentifier, _> = invalid_base64.parse();
    assert!(matches!(result, Err(CryptoError::Base64DecodeError(_))));
}

#[test]
fn test_error_handling_unknown_algorithm() {
    // Create bytes with unknown algorithm identifier
    let mut bytes = vec![b'X']; // Unknown algorithm
    bytes.extend_from_slice(&[0u8; 32]);

    let result = PublicKey::from_bytes(&bytes);
    assert!(matches!(result, Err(CryptoError::UnknownAlgorithm(_))));

    let result = DigestIdentifier::from_bytes(&bytes);
    assert!(matches!(result, Err(CryptoError::UnknownAlgorithm(_))));
}

#[test]
fn test_keypair_persistence_and_recovery() {
    // Test that we can persist and recover a keypair
    let original_keypair =
        KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
    let message = b"test message";

    // Get secret key bytes
    let secret_bytes = original_keypair.secret_key_bytes().unwrap();

    // Create new keypair from secret key
    let recovered_keypair = KeyPair::from_secret_key(&secret_bytes).unwrap();

    // Verify both keypairs produce same public key
    assert_eq!(
        original_keypair.public_key_bytes(),
        recovered_keypair.public_key_bytes()
    );

    // Verify both can sign and verify
    let sig1 = original_keypair.sign(message).unwrap();
    let sig2 = recovered_keypair.sign(message).unwrap();

    let public_key = original_keypair.public_key();
    assert!(public_key.verify(message, &sig1).is_ok());
    assert!(public_key.verify(message, &sig2).is_ok());
}
