//! Hybrid post-quantum payload encryption for sink deliveries.
//!
//! Suite `HPKE-v1-hybrid12` (see [`SUITE_ID`]): the sender combines an
//! ephemeral X25519 Diffie-Hellman with an ML-KEM-768 encapsulation, feeds
//! both shared secrets through HKDF-SHA256 and encrypts the canonical
//! delivery body with AES-256-GCM. The node only ever holds recipient
//! *public* keys; private keys live on the receiver side.
//!
//! The wire [`WireEnvelope`] is JSON and is what gets signed by
//! `sign_delivery` and carried by every transport, so receivers implement
//! decryption once. `key_id` (and `suite`) travel both inside the envelope
//! and as transport headers/metadata for routing without decrypting.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use ave_common::sink::{
    SINK_HYBRID_PUBLIC_KEY_LEN, SinkEncryptionConfig,
    parse_sink_hybrid_public_key,
};
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use ml_kem::{
    Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768,
    array::Array,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::sink::SinkError;

/// Suite identifier pinned on the wire. A future suite gets a new id and
/// goes through the same `key_id` versioning; ids are never reused.
pub const SUITE_ID: &str = "HPKE-v1-hybrid12";

/// X25519 public key length in bytes.
const X25519_PUBLIC_LEN: usize = 32;
/// ML-KEM-768 encapsulation key length in bytes.
const MLKEM768_PUBLIC_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length in bytes.
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// AES-256-GCM key length in bytes.
const AES256_KEY_LEN: usize = 32;
/// Upper bound of the *fixed* per-event encryption overhead on the wire:
/// KEM encapsulations, nonce, tag, `key_id`/`suite` and JSON framing. The
/// ciphertext itself scales with the body (base64 of cleartext + 16-byte
/// tag), so the total envelope is `b64(n + 16) + <= MAX bytes`.
/// Pinned by `envelope_overhead_is_bounded`.
pub const MAX_ENCRYPTION_OVERHEAD_BYTES: usize = 2048;

/// Wire envelope carried as the delivery body when encryption is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    /// Suite that produced this envelope (see [`SUITE_ID`]).
    pub suite: String,
    /// Recipient key that must decrypt it.
    pub key_id: String,
    /// Ephemeral X25519 public key (URL-safe base64, no padding).
    pub eph_pub: String,
    /// ML-KEM-768 ciphertext (URL-safe base64, no padding).
    pub enc_ct: String,
    /// AES-GCM nonce (URL-safe base64, no padding).
    pub nonce: String,
    /// Encrypted canonical body plus 16-byte tag (URL-safe base64).
    pub ciphertext: String,
}

/// Result of encrypting one delivery body.
#[derive(Debug, Clone)]
pub struct EncryptedDelivery {
    /// Serialized [`WireEnvelope`] ready to sign and send.
    pub envelope_json: Vec<u8>,
    /// Recipient key used, for transport headers/metadata.
    pub key_id: String,
}

/// Recipient keypair. The public half is encoded into the sink config;
/// the private half never leaves the receiver. Tests hold it in memory.
pub struct RecipientKeyPair {
    /// Identifier used as `current_key_id` in configs.
    pub key_id: String,
    x_secret: [u8; 32],
    mlkem_dk: DecapsulationKey<MlKem768>,
    /// Value for `SinkEncryptionKey.public_key` (`X:` + base64url).
    pub public_config_string: String,
}

/// Generate a fresh recipient keypair for tests and receiver setup.
pub fn generate_recipient_keypair(key_id: &str) -> RecipientKeyPair {
    let x_secret = StaticSecret::random();
    let x_public = PublicKey::from(&x_secret);
    let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair();
    let mut raw = Vec::with_capacity(SINK_HYBRID_PUBLIC_KEY_LEN);
    raw.extend_from_slice(x_public.as_bytes());
    raw.extend_from_slice(&mlkem_ek.to_bytes());
    let public_config_string =
        format!("X:{}", BASE64_URL_SAFE_NO_PAD.encode(raw));
    RecipientKeyPair {
        key_id: key_id.to_owned(),
        x_secret: x_secret.to_bytes(),
        mlkem_dk,
        public_config_string,
    }
}

/// Encrypt one canonical delivery body for the current key of `config`.
///
/// Returns `Ok(None)` when encryption is absent or disabled so callers keep
/// the cleartext path untouched. A missing current key or malformed public
/// key is a deterministic configuration error (permanent, never retried).
/// Every enabled attempt is counted in `core_sink_encrypt_events`.
pub fn encrypt_payload(
    plaintext: &[u8],
    sink_name: &str,
    config: &SinkEncryptionConfig,
) -> Result<Option<EncryptedDelivery>, SinkError> {
    if !config.enabled {
        return Ok(None);
    }
    let outcome = encrypt_inner(plaintext, config);
    if let Some(metrics) = crate::metrics::try_core_metrics() {
        let label = match &outcome {
            Ok(_) => "success",
            Err(SinkError::Delivery {
                retryable: true, ..
            }) => "transient",
            Err(_) => "permanent",
        };
        metrics.observe_sink_encrypt(sink_name, label);
    }
    outcome.map(Some)
}

fn encrypt_inner(
    plaintext: &[u8],
    config: &SinkEncryptionConfig,
) -> Result<EncryptedDelivery, SinkError> {
    let Some(entry) = config
        .keys
        .iter()
        .find(|k| k.key_id == config.current_key_id)
    else {
        return Err(SinkError::Rejected {
            message: format!(
                "sink encryption misconfigured: current_key_id '{}' matches no listed key",
                config.current_key_id
            ),
        });
    };
    let raw =
        parse_sink_hybrid_public_key(&entry.public_key).map_err(|reason| {
            SinkError::Rejected {
                message: format!(
                    "sink encryption misconfigured for key_id '{}': {reason}",
                    entry.key_id
                ),
            }
        })?;
    let (x_public_bytes, mlkem_public_bytes) = raw.split_at(X25519_PUBLIC_LEN);
    let mut x_public_arr = [0_u8; 32];
    x_public_arr.copy_from_slice(x_public_bytes);
    let x_public = PublicKey::from(x_public_arr);
    // Lengths are pre-checked: `parse_sink_hybrid_public_key` guarantees
    // 1216 bytes, so the ML-KEM part is exactly 1184 bytes.
    if mlkem_public_bytes.len() != MLKEM768_PUBLIC_LEN {
        return Err(SinkError::Rejected {
            message: format!(
                "sink encryption misconfigured for key_id '{}': invalid ML-KEM public key",
                entry.key_id
            ),
        });
    }
    let mlkem_ek = EncapsulationKey::<MlKem768>::new(
        &Array::try_from(mlkem_public_bytes).map_err(|_| {
            SinkError::Rejected {
                message: format!(
                    "sink encryption misconfigured for key_id '{}': invalid ML-KEM public key",
                    entry.key_id
                ),
            }
        })?,
    )
    .map_err(|_| SinkError::Rejected {
        message: format!(
            "sink encryption misconfigured for key_id '{}': invalid ML-KEM public key",
            entry.key_id
        ),
    })?;

    let ephemeral = EphemeralSecret::random();
    let ephemeral_public = PublicKey::from(&ephemeral);
    let mut ss1 = ephemeral.diffie_hellman(&x_public).to_bytes();
    let (ct, mut ss2) = mlkem_ek.encapsulate();
    let mut ss2_bytes = ss2.to_vec();
    ss2.zeroize();

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&ss1);
    ikm.extend_from_slice(&ss2_bytes);
    let mut salt = Vec::with_capacity(64 + SUITE_ID.len() + entry.key_id.len());
    salt.extend_from_slice(ephemeral_public.as_bytes());
    salt.extend_from_slice(&x_public_arr);
    let info = format!("ave-sink-hpke-v1:{SUITE_ID}:{}", entry.key_id);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut key_bytes = [0_u8; AES256_KEY_LEN];
    hkdf.expand(info.as_bytes(), &mut key_bytes).map_err(|_| {
        SinkError::Delivery {
            message: "sink encryption failed to derive message key".to_string(),
            retryable: false,
            retry_after_ms: None,
        }
    })?;
    ss1.zeroize();
    ss2_bytes.zeroize();
    ikm.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| {
        SinkError::Delivery {
            message: "sink encryption failed to init cipher".to_string(),
            retryable: false,
            retry_after_ms: None,
        }
    })?;
    key_bytes.zeroize();
    let mut nonce_bytes = [0_u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|_| SinkError::Delivery {
        message: "sink encryption failed to sample nonce".to_string(),
        retryable: true,
        retry_after_ms: None,
    })?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext =
        cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| SinkError::Delivery {
                message: "sink encryption failed".to_string(),
                retryable: false,
                retry_after_ms: None,
            })?;

    let envelope = WireEnvelope {
        suite: SUITE_ID.to_owned(),
        key_id: entry.key_id.clone(),
        eph_pub: BASE64_URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
        enc_ct: BASE64_URL_SAFE_NO_PAD.encode(ct.to_vec()),
        nonce: BASE64_URL_SAFE_NO_PAD.encode(nonce.as_slice()),
        ciphertext: BASE64_URL_SAFE_NO_PAD.encode(ciphertext),
    };
    let envelope_json =
        serde_json::to_vec(&envelope).map_err(|e| SinkError::Delivery {
            message: format!("sink encryption failed to serialize: {e}"),
            retryable: false,
            retry_after_ms: None,
        })?;
    Ok(EncryptedDelivery {
        envelope_json,
        key_id: entry.key_id.clone(),
    })
}

/// Decrypt a wire envelope with one of the recipient's private keys.
///
/// Used by test receivers (the production node never decrypts); external
/// receivers implement the same steps from the documented suite.
pub fn decrypt_envelope(
    envelope_json: &[u8],
    recipients: &[RecipientKeyPair],
) -> Result<Vec<u8>, SinkError> {
    let envelope: WireEnvelope = serde_json::from_slice(envelope_json)
        .map_err(|e| SinkError::Rejected {
            message: format!("sink envelope is not valid JSON: {e}"),
        })?;
    if envelope.suite != SUITE_ID {
        return Err(SinkError::Rejected {
            message: format!(
                "unsupported sink encryption suite '{}'",
                envelope.suite
            ),
        });
    }
    let Some(recipient) =
        recipients.iter().find(|r| r.key_id == envelope.key_id)
    else {
        return Err(SinkError::Rejected {
            message: format!(
                "unknown sink encryption key_id '{}'",
                envelope.key_id
            ),
        });
    };
    let eph_pub_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(envelope.eph_pub.as_bytes())
        .map_err(|e| SinkError::Rejected {
            message: format!("sink envelope has invalid eph_pub: {e}"),
        })?;
    if eph_pub_bytes.len() != X25519_PUBLIC_LEN {
        return Err(SinkError::Rejected {
            message: "sink envelope eph_pub has wrong length".to_string(),
        });
    }
    let mut eph_arr = [0_u8; 32];
    eph_arr.copy_from_slice(&eph_pub_bytes);
    let eph_public = PublicKey::from(eph_arr);
    let x_secret = StaticSecret::from(recipient.x_secret);
    let mut ss1 = x_secret.diffie_hellman(&eph_public).to_bytes();

    let ct_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(envelope.enc_ct.as_bytes())
        .map_err(|e| SinkError::Rejected {
            message: format!("sink envelope has invalid enc_ct: {e}"),
        })?;
    if ct_bytes.len() != MLKEM768_CIPHERTEXT_LEN {
        return Err(SinkError::Rejected {
            message: "sink envelope enc_ct has wrong length".to_string(),
        });
    }
    let ct: Ciphertext<MlKem768> =
        Array::try_from(&ct_bytes[..]).map_err(|_| SinkError::Rejected {
            message: "sink envelope enc_ct has wrong length".to_string(),
        })?;
    let mut ss2 = recipient.mlkem_dk.decapsulate(&ct);
    let mut ss2_bytes = ss2.to_vec();
    ss2.zeroize();

    let nonce_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(envelope.nonce.as_bytes())
        .map_err(|e| SinkError::Rejected {
            message: format!("sink envelope has invalid nonce: {e}"),
        })?;
    if nonce_bytes.len() != 12 {
        return Err(SinkError::Rejected {
            message: "sink envelope nonce has wrong length".to_string(),
        });
    }
    let ciphertext = BASE64_URL_SAFE_NO_PAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|e| SinkError::Rejected {
            message: format!("sink envelope has invalid ciphertext: {e}"),
        })?;

    let mut x_public_arr = [0_u8; 32];
    x_public_arr.copy_from_slice(
        &parse_sink_hybrid_public_key(&recipient.public_config_string)
            .map_err(|reason| SinkError::Rejected {
                message: format!("recipient public key invalid: {reason}"),
            })?[..X25519_PUBLIC_LEN],
    );
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&ss1);
    ikm.extend_from_slice(&ss2_bytes);
    let mut salt =
        Vec::with_capacity(64 + SUITE_ID.len() + envelope.key_id.len());
    salt.extend_from_slice(&eph_arr);
    salt.extend_from_slice(&x_public_arr);
    let info = format!("ave-sink-hpke-v1:{SUITE_ID}:{}", envelope.key_id);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut key_bytes = [0_u8; AES256_KEY_LEN];
    hkdf.expand(info.as_bytes(), &mut key_bytes).map_err(|_| {
        SinkError::Rejected {
            message: "sink envelope key derivation failed".to_string(),
        }
    })?;
    ss1.zeroize();
    ss2_bytes.zeroize();
    ikm.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| {
        SinkError::Rejected {
            message: "sink envelope cipher init failed".to_string(),
        }
    })?;
    key_bytes.zeroize();
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
        SinkError::Rejected {
            message: "sink envelope failed authentication".to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disabled_config() -> SinkEncryptionConfig {
        SinkEncryptionConfig::default()
    }

    fn enabled_config(
        extra_key_ids: &[&str],
    ) -> (SinkEncryptionConfig, Vec<RecipientKeyPair>) {
        let mut recipients = vec![recipient_keypair("v1")];
        recipients.extend(extra_key_ids.iter().map(|id| recipient_keypair(id)));
        let keys = recipients
            .iter()
            .map(|r| ave_common::sink::SinkEncryptionKey {
                key_id: r.key_id.clone(),
                public_key: r.public_config_string.clone(),
            })
            .collect();
        (
            SinkEncryptionConfig {
                enabled: true,
                current_key_id: "v1".to_owned(),
                keys,
            },
            recipients,
        )
    }

    fn recipient_keypair(key_id: &str) -> RecipientKeyPair {
        generate_recipient_keypair(key_id)
    }

    #[test]
    fn disabled_config_returns_no_encryption() {
        let out = encrypt_payload(b"hello", "unit-sink", &disabled_config())
            .expect("disabled must not fail");
        assert!(out.is_none());
    }

    #[test]
    fn roundtrip_recovers_plaintext() {
        let (config, recipients) = enabled_config(&[]);
        let plaintext = br#"{"subject_id":"s","sn":7}"#;
        let encrypted = encrypt_payload(plaintext, "unit-sink", &config)
            .expect("encrypt must succeed")
            .expect("enabled config must encrypt");
        assert_eq!(encrypted.key_id, "v1");
        let envelope: WireEnvelope =
            serde_json::from_slice(&encrypted.envelope_json)
                .expect("envelope is JSON");
        assert_eq!(envelope.suite, SUITE_ID);
        assert_eq!(envelope.key_id, "v1");
        let recovered = decrypt_envelope(&encrypted.envelope_json, &recipients)
            .expect("decrypt must succeed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn ciphertexts_are_unique_per_message() {
        let (config, _) = enabled_config(&[]);
        let first = encrypt_payload(b"same", "unit-sink", &config)
            .expect("encrypt must succeed")
            .expect("enabled");
        let second = encrypt_payload(b"same", "unit-sink", &config)
            .expect("encrypt must succeed")
            .expect("enabled");
        assert_ne!(
            first.envelope_json, second.envelope_json,
            "fresh ephemeral keys must randomize every message"
        );
        let first_env: WireEnvelope =
            serde_json::from_slice(&first.envelope_json).expect("JSON");
        let second_env: WireEnvelope =
            serde_json::from_slice(&second.envelope_json).expect("JSON");
        assert_ne!(first_env.nonce, second_env.nonce);
        assert_ne!(first_env.eph_pub, second_env.eph_pub);
    }

    #[test]
    fn unknown_current_key_is_rejected() {
        let (mut config, _) = enabled_config(&[]);
        config.current_key_id = "v9".to_owned();
        let err =
            encrypt_payload(b"x", "unit-sink", &config).expect_err("must fail");
        assert!(
            matches!(err, SinkError::Rejected { .. }),
            "unknown current key is permanent: {err:?}"
        );
    }

    #[test]
    fn tampered_envelope_fails_authentication() {
        let (config, recipients) = enabled_config(&[]);
        let encrypted = encrypt_payload(b"secret", "unit-sink", &config)
            .expect("encrypt")
            .expect("enabled");
        // Tampering any security field breaks authentication.
        for mutate in [
            |envelope: &mut WireEnvelope| {
                let mut ct = BASE64_URL_SAFE_NO_PAD
                    .decode(envelope.ciphertext.as_bytes())
                    .expect("valid b64");
                ct[0] ^= 0x01;
                envelope.ciphertext = BASE64_URL_SAFE_NO_PAD.encode(ct);
            },
            |envelope: &mut WireEnvelope| {
                let mut nonce = BASE64_URL_SAFE_NO_PAD
                    .decode(envelope.nonce.as_bytes())
                    .expect("valid b64");
                nonce[0] ^= 0x01;
                envelope.nonce = BASE64_URL_SAFE_NO_PAD.encode(nonce);
            },
            |envelope: &mut WireEnvelope| {
                let mut eph = BASE64_URL_SAFE_NO_PAD
                    .decode(envelope.eph_pub.as_bytes())
                    .expect("valid b64");
                eph[0] ^= 0x01;
                envelope.eph_pub = BASE64_URL_SAFE_NO_PAD.encode(eph);
            },
        ] {
            let mut envelope: WireEnvelope =
                serde_json::from_slice(&encrypted.envelope_json).expect("JSON");
            mutate(&mut envelope);
            let tampered = serde_json::to_vec(&envelope).expect("JSON");
            let err = decrypt_envelope(&tampered, &recipients)
                .expect_err("must fail");
            assert!(
                matches!(err, SinkError::Rejected { .. }),
                "tamper is permanent: {err:?}"
            );
        }
    }

    #[test]
    fn unknown_key_id_fails_decrypt() {
        let (config, _) = enabled_config(&[]);
        let encrypted = encrypt_payload(b"secret", "unit-sink", &config)
            .expect("encrypt")
            .expect("enabled");
        let other = recipient_keypair("v2");
        let err = decrypt_envelope(&encrypted.envelope_json, &[other])
            .expect_err("must fail");
        assert!(matches!(err, SinkError::Rejected { .. }));
    }

    #[test]
    fn swapped_key_id_fails_authentication() {
        let (config, recipients) = enabled_config(&["v2"]);
        let encrypted = encrypt_payload(b"secret", "unit-sink", &config)
            .expect("encrypt")
            .expect("enabled");
        // Envelope claims v2 but carries v1's ciphertext: the v2 private
        // key cannot open it.
        let mut envelope: WireEnvelope =
            serde_json::from_slice(&encrypted.envelope_json).expect("JSON");
        assert_eq!(envelope.key_id, "v1");
        envelope.key_id = "v2".to_owned();
        let swapped = serde_json::to_vec(&envelope).expect("JSON");
        let err =
            decrypt_envelope(&swapped, &recipients).expect_err("must fail");
        assert!(
            matches!(err, SinkError::Rejected { .. }),
            "wrong-key decrypt is permanent: {err:?}"
        );
    }

    #[test]
    fn unsupported_suite_fails_decrypt() {
        let (config, recipients) = enabled_config(&[]);
        let encrypted = encrypt_payload(b"secret", "unit-sink", &config)
            .expect("encrypt")
            .expect("enabled");
        let mut envelope: WireEnvelope =
            serde_json::from_slice(&encrypted.envelope_json).expect("JSON");
        envelope.suite = "FUTURE-v9".to_owned();
        let bad = serde_json::to_vec(&envelope).expect("JSON");
        let err = decrypt_envelope(&bad, &recipients).expect_err("must fail");
        assert!(matches!(err, SinkError::Rejected { .. }));
    }

    #[test]
    fn envelope_overhead_is_bounded() {
        let (config, _) = enabled_config(&[]);
        // The fixed overhead (KEM/nonce/tag/framing) is constant; the
        // ciphertext scales as base64(cleartext + tag). (Intake caps
        // cleartext at 100k, so the 1 MiB wire cap is unreachable for
        // encrypted deliveries; this pins the constant part.)
        for size in [0, 1, 1024, 100 * 1024] {
            let plaintext = vec![0xA5_u8; size];
            let encrypted = encrypt_payload(&plaintext, "unit-sink", &config)
                .expect("encrypt")
                .expect("enabled");
            // Base64 of body + tag, then everything else is the fixed part.
            let body_b64_len = (plaintext.len() + 16 + 2) / 3 * 4;
            let fixed =
                encrypted.envelope_json.len().saturating_sub(body_b64_len);
            assert!(
                fixed <= MAX_ENCRYPTION_OVERHEAD_BYTES,
                "fixed overhead {fixed} exceeds bound at size {size}"
            );
        }
    }
}
