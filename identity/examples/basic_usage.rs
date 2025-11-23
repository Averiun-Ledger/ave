//! Basic usage example of the crypto module
//!
//! Run with: cargo run --example basic_usage

use ave_identity::{
    hash::{Blake3Hasher, DigestIdentifier, Hash, HashAlgorithm},
    keys::{DSA, DSAlgorithm, Ed25519Signer, PublicKey, SignatureIdentifier},
};

fn main() {
    println!("=== Crypto Module Demo ===\n");

    // Hash examples
    hash_example();
    println!();

    // Signature examples
    signature_example();
    println!();

    // Deterministic key generation
    deterministic_keys_example();
    println!();

    // Algorithm detection
    algorithm_detection_example();
}

fn hash_example() {
    println!("--- Hash Example ---");

    let hasher = Blake3Hasher;
    let data = b"Hello, Ave Ledger!";

    println!("Data: {:?}", String::from_utf8_lossy(data));

    // Compute hash
    let hash = hasher.hash(data);
    println!("Algorithm: {}", hash.algorithm());

    // Convert to string representation (internally uses Base64)
    let hash_str = hash.to_string();
    println!("Hash (string): {}", hash_str);
    println!(
        "  -> First char indicates algorithm (B=Blake3): {}",
        &hash_str.chars().next().unwrap()
    );

    // Verify hash
    println!("Verification with correct data: {}", hash.verify(data));
    println!(
        "Verification with wrong data: {}",
        hash.verify(b"Wrong data")
    );

    // Parse from string
    let parsed_hash: DigestIdentifier = hash_str.parse().unwrap();
    println!("Parsed algorithm: {}", parsed_hash.algorithm());
    println!("Hashes match: {}", hash == parsed_hash);
}

fn signature_example() {
    println!("--- Signature Example ---");

    // Generate keypair
    let signer = Ed25519Signer::generate().expect("Failed to generate keypair");
    println!("Generated Ed25519 keypair");

    // Create public key wrapper with algorithm identifier
    let public_key =
        PublicKey::new(DSAlgorithm::Ed25519, signer.public_key_bytes())
            .unwrap();

    println!("Public key (string): {}", public_key);

    // Sign message
    let message = b"This is a signed message";
    println!("\nMessage: {:?}", String::from_utf8_lossy(message));

    let signature = signer.sign(message).unwrap();
    println!("Signature algorithm: {}", signature.algorithm());

    // Convert to string representation
    let sig_str = signature.to_string();
    println!("Signature (string with ID): {}", sig_str);
    println!(
        "  -> First char indicates algorithm (E=Ed25519): {}",
        &sig_str.chars().next().unwrap()
    );

    // Verify signature
    let verify_result = public_key.verify(message, &signature);
    println!("\nSignature verification: {:?}", verify_result);

    // Try to verify with wrong message
    let wrong_message = b"Wrong message";
    let verify_wrong = public_key.verify(wrong_message, &signature);
    println!("Verification with wrong message: {:?}", verify_wrong);

    // Parse signature from string
    let parsed_sig: SignatureIdentifier = sig_str.parse().unwrap();
    println!("\nParsed signature algorithm: {}", parsed_sig.algorithm());

    // Parse public key from string
    let pubkey_str = public_key.to_string();
    let parsed_pubkey: PublicKey = pubkey_str.parse().unwrap();
    println!("Parsed public key algorithm: {}", parsed_pubkey.algorithm());

    // Verify with parsed values
    let final_verify = parsed_pubkey.verify(message, &parsed_sig);
    println!("Verification with parsed values: {:?}", final_verify);
}

fn deterministic_keys_example() {
    println!("--- Deterministic Key Generation ---");

    // Use a specific seed for deterministic key generation (32 bytes)
    let seed = [42u8; 32];
    println!("Seed (32 bytes): {:?}", seed);

    let signer1 =
        Ed25519Signer::from_seed(&seed).expect("Failed to create signer");
    let signer2 =
        Ed25519Signer::from_seed(&seed).expect("Failed to create signer");

    let pk1 = PublicKey::new(DSAlgorithm::Ed25519, signer1.public_key_bytes())
        .unwrap();
    let pk2 = PublicKey::new(DSAlgorithm::Ed25519, signer2.public_key_bytes())
        .unwrap();
    println!("Public key 1: {}", pk1);
    println!("Public key 2: {}", pk2);

    let keys_match = signer1.public_key_bytes() == signer2.public_key_bytes();
    println!("Keys generated from same seed match: {}", keys_match);

    // Example with arbitrary data (passphrase)
    println!("\n--- Key Derivation from Passphrase ---");
    let passphrase = b"my secure passphrase for crypto keys";
    println!("Passphrase: {:?}", String::from_utf8_lossy(passphrase));

    let signer3 = Ed25519Signer::derive_from_data(passphrase)
        .expect("Failed to derive keys");
    let signer4 = Ed25519Signer::derive_from_data(passphrase)
        .expect("Failed to derive keys");

    let pk3 = PublicKey::new(DSAlgorithm::Ed25519, signer3.public_key_bytes())
        .unwrap();
    let pk4 = PublicKey::new(DSAlgorithm::Ed25519, signer4.public_key_bytes())
        .unwrap();
    println!("Derived public key 1: {}", pk3);
    println!("Derived public key 2: {}", pk4);

    let derived_keys_match =
        signer3.public_key_bytes() == signer4.public_key_bytes();
    println!(
        "Keys derived from same passphrase match: {}",
        derived_keys_match
    );
}

fn algorithm_detection_example() {
    println!("--- Algorithm Detection ---");

    // Create hash
    let hasher = Blake3Hasher;
    let hash = hasher.hash(b"test data");
    let hash_str = hash.to_string();

    println!("Hash string: {}", hash_str);

    // The first byte (first char) identifies the algorithm
    println!(
        "Algorithm identifier: {} (raw byte: B=0x42)",
        hash_str.chars().next().unwrap()
    );

    // When parsing, the algorithm is automatically detected
    let parsed: DigestIdentifier = hash_str.parse().unwrap();
    println!(
        "Detected algorithm: {} ({})",
        parsed.algorithm(),
        match parsed.algorithm() {
            HashAlgorithm::Blake3 => "Blake3",
        }
    );

    // Same for signatures
    let signer = Ed25519Signer::generate().expect("Failed to generate keypair");
    let signature = signer.sign(b"message").unwrap();
    let sig_str = signature.to_string();

    println!("\nSignature string: {}", sig_str);
    println!(
        "Algorithm identifier: {} (raw byte: E=0x45)",
        sig_str.chars().next().unwrap()
    );

    let parsed_sig: SignatureIdentifier = sig_str.parse().unwrap();
    println!(
        "Detected algorithm: {} ({})",
        parsed_sig.algorithm(),
        match parsed_sig.algorithm() {
            DSAlgorithm::Ed25519 => "Ed25519",
        }
    );

    println!("\n✓ Algorithm detection works automatically!");
    println!(
        "  Just by looking at the first character (which encodes the first byte),"
    );
    println!("  we know which algorithm was used:");
    println!("    B (0x42) = Blake3");
    println!("    E (0x45) = Ed25519");
}
