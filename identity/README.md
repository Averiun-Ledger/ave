# ave-identity

`ave-identity` is the cryptographic crate of the Ave workspace.

It provides a small, explicit API for hashing, key management, signing and
signature verification. Public values carry an algorithm identifier so they can
be serialized and parsed without extra metadata.

This crate is free software and is distributed under the `AGPL-3.0-only`
license.

## Installation

```toml
[dependencies]
ave-identity = "0.3.0"
```

## What it includes

- Blake3 digests with compact string encoding
- Ed25519 key generation, signing and verification
- Public key and signature wrappers with algorithm identifiers
- Signed payloads with timestamp and content hash
- PKCS#8 DER import and export for secret keys

## Supported algorithms

- Hash: Blake3 (`B`)
- Signature: Ed25519 (`E`)

## Basic example

```rust
use ave_identity::{BLAKE3_HASHER, Hash, KeyPair, KeyPairAlgorithm};

let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519)?;
let digest = BLAKE3_HASHER.hash(b"hello world");
let signature = keypair.sign(digest.hash_bytes())?;

keypair.public_key().verify(digest.hash_bytes(), &signature)?;
# Ok::<(), ave_identity::CryptoError>(())
```

## Data model

- `DigestIdentifier`: hash bytes plus algorithm
- `PublicKey`: public key bytes plus algorithm
- `SignatureIdentifier`: signature bytes plus algorithm
- `Signature`: signer, timestamp, content hash and signature value
- `Signed<T>`: content bundled with `Signature`

String encodings use URL-safe Base64 without padding. The first character is the
algorithm identifier.

## Security notes

- Secret keys are stored in encrypted memory through `memsecurity`.
- Secret keys are decrypted only when signing.
- `KeyPair::to_bytes()` and `KeyPair::to_secret_der()` expose secret key
  material. Use them only when persistence or key transport is required.
- `Ed25519Signer::derive_from_data()` is deterministic, but it is not a
  password-hard KDF.

## Development

Run the crate tests:

```bash
cargo test -p ave-identity
```

Run the example:

```bash
cargo run -p ave-identity --example basic_usage
```
