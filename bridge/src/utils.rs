use ave_common::identity::KeyPair;
use pkcs8::{Document, EncryptedPrivateKeyInfo, PrivateKeyInfo, pkcs5};

use getrandom::fill;
use std::fs;

use crate::config::Config;
use crate::error::BridgeError;

const PBKDF2_ITERATIONS: u32 = 200_000;

pub fn key_pair(config: &Config, password: &str) -> Result<KeyPair, BridgeError> {
    if fs::metadata(&config.keys_path).is_err() {
        fs::create_dir_all(&config.keys_path).map_err(|e| {
            BridgeError::KeyDirectoryCreation(e.to_string())
        })?;
    }

    let path = config.keys_path.join("node_private.der");
    match fs::metadata(&path) {
        Ok(_) => {
            let document = Document::read_der_file(path).map_err(|e| {
                BridgeError::KeyRead(e.to_string())
            })?;
            let enc_pk = EncryptedPrivateKeyInfo::try_from(document.as_bytes())
                .map_err(|e| {
                    BridgeError::KeyRead(e.to_string())
                })?;
            let dec_pk = enc_pk.decrypt(password).map_err(|e| {
                BridgeError::KeyDecrypt(e.to_string())
            })?;

            let key_pair = KeyPair::from_secret_der(dec_pk.as_bytes())
                .map_err(|e| {
                    BridgeError::KeyRestore(e.to_string())
                })?;
            Ok(key_pair)
        }
        Err(_) => {
            let key_pair =
                config.node.keypair_algorithm.generate_keypair().map_err(
                    |e| BridgeError::KeyGeneration(e.to_string()),
                )?;

            let der = key_pair.to_secret_der().map_err(|e| {
                BridgeError::KeyGeneration(e.to_string())
            })?;
            let pk =
                PrivateKeyInfo::try_from(der.as_slice()).map_err(|e| {
                    BridgeError::KeyGeneration(e.to_string())
                })?;
            let mut salt = [0u8; 32];
            let mut iv = [0u8; 16];
            fill(&mut salt).map_err(|e| {
                BridgeError::KeyEncrypt(e.to_string())
            })?;
            fill(&mut iv).map_err(|e| {
                BridgeError::KeyEncrypt(e.to_string())
            })?;

            let params = pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(
                PBKDF2_ITERATIONS,
                &salt,
                &iv,
            )
            .map_err(|e| {
                BridgeError::KeyEncrypt(e.to_string())
            })?;
            let enc_pk =
                pk.encrypt_with_params(params, password).map_err(|_| {
                    BridgeError::KeyEncrypt(
                        "encryption algorithm failed".to_owned(),
                    )
                })?;
            enc_pk.write_der_file(path).map_err(|e| {
                BridgeError::KeyWrite(e.to_string())
            })?;
            Ok(key_pair)
        }
    }
}
