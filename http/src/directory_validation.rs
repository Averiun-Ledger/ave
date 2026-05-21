use std::fs;
use std::path::Path;

use ave_bridge::config::Config as BridgeConfig;
use tracing::{info, warn};

const TARGET: &str = "ave::http::validation";

/// Validate filesystem permissions for the paths that `ave-http` manages
/// directly (auth database and TLS certificates).
///
/// This check is **passive**: it never creates directories or files.
/// If a path does not exist yet, it only verifies that the parent
/// directory would allow its creation.
pub fn validate_http_paths(config: &BridgeConfig) -> Result<(), String> {
    // 1. Auth database directory
    check_dir_writable(&config.auth.database_path, "auth.database_path")?;

    // 2. TLS certificate
    if let Some(ref cert_path) = config.http.https_cert_path {
        let need_write = config.http.self_signed_cert.enabled;
        check_file_or_parent(cert_path, "https_cert_path", need_write)?;
    }

    // 3. TLS private key
    if let Some(ref key_path) = config.http.https_private_key_path {
        let need_write = config.http.self_signed_cert.enabled;
        check_file_or_parent(key_path, "https_private_key_path", need_write)?;
    }

    info!(target: TARGET, "HTTP path permissions verified successfully");
    Ok(())
}

/// Validate only the logging directory. This must run **before**
/// `init_logging` so we fail fast if the log directory is not writable.
pub fn validate_logging_path(config: &BridgeConfig) -> Result<(), String> {
    if config.logging.output.file {
        check_dir_writable(&config.logging.file_path, "logging.file_path")?;
    }
    Ok(())
}

/// Check that a directory exists and is writable.
/// If it does not exist, check the nearest existing ancestor.
fn check_dir_writable(path: &Path, name: &str) -> Result<(), String> {
    let target = if path.exists() {
        if !path.is_dir() {
            return Err(format!(
                "{name} ('{}') exists but is not a directory",
                path.display()
            ));
        }
        path
    } else {
        // Find the first existing ancestor
        let mut ancestor = path;
        while !ancestor.exists() {
            match ancestor.parent() {
                Some(p) => ancestor = p,
                None => {
                    return Err(format!(
                        "{name} ('{}') does not exist and has no existing parent directory",
                        path.display()
                    ));
                }
            }
        }
        if !ancestor.is_dir() {
            return Err(format!(
                "{name} ancestor ('{}') exists but is not a directory",
                ancestor.display()
            ));
        }
        warn!(
            target: TARGET,
            "{name} ('{}') does not exist yet; checking nearest ancestor ('{}') for writability",
            path.display(),
            ancestor.display()
        );
        ancestor
    };

    // Verify real writability with a temporary file (no leftover on success)
    let test_file = target.join(format!(".ave_write_test_{}", rand::random::<u32>()));
    match fs::File::create(&test_file) {
        Ok(_) => {
            let _ = fs::remove_file(&test_file);
        }
        Err(e) => {
            return Err(format!(
                "{name} ('{}') is not writable: {e}",
                target.display()
            ));
        }
    }

    Ok(())
}

/// Check a file path.
/// - If it exists: verify readability (and writability when `need_write` is true).
/// - If it does not exist: verify the parent directory is writable.
fn check_file_or_parent(
    path: &Path,
    name: &str,
    need_write: bool,
) -> Result<(), String> {
    if path.exists() {
        if !path.is_file() {
            return Err(format!(
                "{name} ('{}') exists but is not a file",
                path.display()
            ));
        }

        // readability
        fs::File::open(path).map_err(|e| {
            format!("{name} ('{}') is not readable: {e}", path.display())
        })?;

        if need_write {
            let test = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(format!(".ave_write_test_{}", rand::random::<u32>()));
            match fs::File::create(&test) {
                Ok(_) => {
                    let _ = fs::remove_file(&test);
                }
                Err(e) => {
                    return Err(format!(
                        "{name} ('{}') is not writable: {e}",
                        path.display()
                    ));
                }
            }
        }

        return Ok(());
    }

    // File does not exist yet — check parent directory
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    check_dir_writable(parent, &format!("{name} parent directory"))
}
