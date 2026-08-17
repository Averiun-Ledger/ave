use ave_common::identity::KeyPair;
use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef, pkcs5};

use getrandom::fill;
use std::fs;

use crate::config::Config;
use crate::error::BridgeError;

const PBKDF2_ITERATIONS: u32 = 200_000;

/// Validate that the keys path (or its nearest existing ancestor) is writable.
pub fn validate_keys_path(path: &std::path::Path) -> Result<(), String> {
    let target = if path.exists() {
        if !path.is_dir() {
            return Err(format!(
                "'{}' exists but is not a directory",
                path.display()
            ));
        }
        path
    } else {
        let mut ancestor = path;
        while !ancestor.exists() {
            match ancestor.parent() {
                Some(p) => ancestor = p,
                None => {
                    return Err(format!(
                        "'{}' does not exist and has no existing parent",
                        path.display()
                    ));
                }
            }
        }
        if !ancestor.is_dir() {
            return Err(format!(
                "ancestor '{}' exists but is not a directory",
                ancestor.display()
            ));
        }
        ancestor
    };

    let test_file = target.join(".ave_write_test");
    match std::fs::File::create(&test_file) {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_file);
        }
        Err(e) => {
            return Err(format!("'{}' is not writable: {e}", target.display()));
        }
    }

    Ok(())
}

pub fn key_pair(
    config: &Config,
    password: &str,
) -> Result<KeyPair, BridgeError> {
    if fs::metadata(&config.keys_path).is_err() {
        fs::create_dir_all(&config.keys_path)
            .map_err(|e| BridgeError::KeyDirectoryCreation(e.to_string()))?;
    }

    let path = config.keys_path.join("node_private.der");
    match fs::metadata(&path) {
        Ok(metadata) => {
            // Self-heal permissions of keys written before the owner-only
            // policy: anything more permissive than 0o600 is tightened on
            // read so existing deployments are not left exposed.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    fs::set_permissions(
                        &path,
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .map_err(|e| {
                        BridgeError::KeyRead(format!(
                            "cannot tighten permissions of '{}': {e}",
                            path.display()
                        ))
                    })?;
                }
            }
            let bytes = fs::read(&path)
                .map_err(|e| BridgeError::KeyRead(e.to_string()))?;
            let enc_pk = EncryptedPrivateKeyInfoRef::try_from(bytes.as_slice())
                .map_err(|e| BridgeError::KeyRead(e.to_string()))?;
            let dec_pk = enc_pk
                .decrypt(password)
                .map_err(|e| BridgeError::KeyDecrypt(e.to_string()))?;

            let key_pair = KeyPair::from_secret_der(dec_pk.as_bytes())
                .map_err(|e| BridgeError::KeyRestore(e.to_string()))?;
            Ok(key_pair)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key_pair = config
                .node
                .keypair_algorithm
                .generate_keypair()
                .map_err(|e| BridgeError::KeyGeneration(e.to_string()))?;

            let der = key_pair
                .to_secret_der()
                .map_err(|e| BridgeError::KeyGeneration(e.to_string()))?;
            let pk = PrivateKeyInfoRef::try_from(der.as_slice())
                .map_err(|e| BridgeError::KeyGeneration(e.to_string()))?;
            let mut salt = [0u8; 32];
            let mut iv = [0u8; 16];
            fill(&mut salt)
                .map_err(|e| BridgeError::KeyEncrypt(e.to_string()))?;
            fill(&mut iv)
                .map_err(|e| BridgeError::KeyEncrypt(e.to_string()))?;

            let params =
                pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(
                    PBKDF2_ITERATIONS,
                    &salt,
                    iv,
                )
                .map_err(|e| BridgeError::KeyEncrypt(e.to_string()))?;
            let enc_pk =
                pk.encrypt_with_params(params, password).map_err(|_| {
                    BridgeError::KeyEncrypt(
                        "encryption algorithm failed".to_owned(),
                    )
                })?;
            // Atomic write with owner-only permissions: a crash mid-write
            // must not leave a corrupt key (the node would not start), and
            // the private key must never be readable by other users (same
            // policy as the HTTP auth key files). A leftover `.tmp` after a
            // crash is harmless: the next start regenerates and renames.
            let tmp_path = path.with_extension("der.tmp");
            fs::write(&tmp_path, enc_pk.as_bytes())
                .map_err(|e| BridgeError::KeyWrite(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &tmp_path,
                    std::fs::Permissions::from_mode(0o600),
                )
                .map_err(|e| BridgeError::KeyWrite(e.to_string()))?;
            }
            fs::rename(&tmp_path, &path)
                .map_err(|e| BridgeError::KeyWrite(e.to_string()))?;
            Ok(key_pair)
        }
        // Any other stat error (permissions, transient IO) must NOT trigger
        // key generation: silently overwriting the key would change the
        // node's peer id and its on-network identity.
        Err(e) => Err(BridgeError::KeyRead(format!(
            "cannot stat '{}': {e}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(keys_path: &std::path::Path) -> Config {
        Config {
            keys_path: keys_path.to_path_buf(),
            ..Config::default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn key_pair_writes_key_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir should be created");
        let config = test_config(dir.path());

        key_pair(&config, "test-password").expect("key pair should generate");

        let key_path = dir.path().join("node_private.der");
        let mode = std::fs::metadata(&key_path)
            .expect("key file should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the private key must be owner-only");
        assert!(
            !dir.path().join("node_private.der.tmp").exists(),
            "the atomic-write temporary file must not linger"
        );
    }

    #[test]
    fn key_pair_restores_the_same_identity_on_second_call() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let config = test_config(dir.path());

        let first =
            key_pair(&config, "test-password").expect("first call generates");
        let second =
            key_pair(&config, "test-password").expect("second call restores");

        assert_eq!(
            first.public_key().to_string(),
            second.public_key().to_string(),
            "the node identity must be stable across restarts"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_pair_tightens_loose_permissions_on_read() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir should be created");
        let config = test_config(dir.path());

        let first =
            key_pair(&config, "test-password").expect("key pair should generate");
        let key_path = dir.path().join("node_private.der");

        // Simulate a key written before the owner-only policy (0644).
        std::fs::set_permissions(
            &key_path,
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod should succeed");

        let second =
            key_pair(&config, "test-password").expect("read should succeed");

        let mode = std::fs::metadata(&key_path)
            .expect("key file should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "loose permissions must be tightened on read"
        );
        assert_eq!(
            first.public_key().to_string(),
            second.public_key().to_string(),
            "tightening permissions must not touch the identity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_pair_does_not_regenerate_on_io_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir should be created");
        let keys_dir = dir.path().join("keys");
        std::fs::create_dir_all(&keys_dir).expect("keys dir should be created");
        let config = test_config(&keys_dir);

        key_pair(&config, "test-password").expect("key pair should generate");
        let key_path = keys_dir.join("node_private.der");
        let original =
            std::fs::read(&key_path).expect("key file should be readable");

        // Make the key file un-statable (no search permission on the
        // directory): a transient IO error must surface as KeyRead, not as
        // a silent identity regeneration.
        std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o000))
            .expect("chmod should succeed");
        let result = key_pair(&config, "test-password");
        std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod restore should succeed");

        assert!(
            matches!(result, Err(BridgeError::KeyRead(_))),
            "an IO error must not regenerate the key, got {result:?}"
        );
        let after =
            std::fs::read(&key_path).expect("key file should be readable");
        assert_eq!(
            original, after,
            "the key material must be untouched after the IO error"
        );
    }
}
