use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use ave_bridge::http::SelfSignedCertConfig;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use time::OffsetDateTime;
use tokio::fs;
use tracing::{error, info, warn};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

const TARGET: &str = "ave::http::cert";

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("Failed to generate certificate: {0}")]
    Generation(String),
    #[error("Failed to write certificate file: {0}")]
    FileWrite(#[from] std::io::Error),
}

/// Generate a new self-signed certificate and private key
pub async fn generate_self_signed_cert(
    config: &SelfSignedCertConfig,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), CertError> {
    info!(target: TARGET, "Generating new self-signed certificate");

    // Create parent directories if they don't exist
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).await?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Generate key pair
    let key_pair = KeyPair::generate()
        .map_err(|e| CertError::Generation(e.to_string()))?;

    // Configure certificate parameters
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, &config.common_name);

    // Set validity period
    let not_before = OffsetDateTime::now_utc();
    let not_after =
        not_before + time::Duration::days(config.validity_days as i64);
    params.not_before = not_before;
    params.not_after = not_after;

    // Add Subject Alternative Names
    let mut san_list = vec![SanType::DnsName(
        config.common_name.clone().try_into().map_err(|e| {
            CertError::Generation(format!("Invalid DNS name: {e}"))
        })?,
    )];

    for san in &config.san {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            san_list.push(SanType::IpAddress(ip));
        } else if let Ok(dns_name) = san.clone().try_into() {
            san_list.push(SanType::DnsName(dns_name));
        }
    }
    params.subject_alt_names = san_list;

    // Generate the certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::Generation(e.to_string()))?;

    // Write certificate and key to files
    fs::write(cert_path, cert.pem()).await?;
    fs::write(key_path, key_pair.serialize_pem()).await?;

    info!(
        target: TARGET,
        "Self-signed certificate generated successfully. Valid until: {}",
        not_after
    );

    Ok(())
}

/// Build the expected set of SANs from configuration.
fn expected_sans(config: &SelfSignedCertConfig) -> HashSet<String> {
    let mut expected = HashSet::new();
    expected.insert(config.common_name.to_lowercase());
    for san in &config.san {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            expected.insert(ip.to_string());
        } else {
            expected.insert(san.to_lowercase());
        }
    }
    expected
}

/// Parse the SANs from a PEM certificate and return them as a normalized set.
fn parse_cert_sans(pem_data: &[u8]) -> Option<HashSet<String>> {
    let (_, pem) = parse_x509_pem(pem_data).ok()?;
    let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;

    let mut sans = HashSet::new();

    let ext = cert.subject_alternative_name().ok()??;
    for gn in &ext.value.general_names {
        match *gn {
            GeneralName::DNSName(dns) => {
                sans.insert(dns.to_lowercase());
            }
            GeneralName::IPAddress(ip_bytes) => {
                let ip = match ip_bytes.len() {
                    4 => std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                        <[u8; 4]>::try_from(ip_bytes).ok()?,
                    )),
                    16 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(ip_bytes).ok()?,
                    )),
                    _ => continue,
                };
                sans.insert(ip.to_string());
            }
            _ => {}
        }
    }

    Some(sans)
}

/// Check if a certificate file exists and is not about to expire
pub async fn cert_needs_renewal(
    config: &SelfSignedCertConfig,
    cert_path: &Path,
    key_path: &Path,
) -> bool {
    // Check if files exist
    if !cert_path.exists() || !key_path.exists() {
        info!(target: TARGET, "Certificate files not found, generation needed");
        return true;
    }

    // Read and parse certificate
    let pem_data = match fs::read(cert_path).await {
        Ok(data) => data,
        Err(e) => {
            warn!(target: TARGET, "Could not read certificate file: {}, forcing renewal", e);
            return true;
        }
    };

    // Check expiration
    match parse_cert_expiry(&pem_data) {
        Some(expiry) => {
            let now = OffsetDateTime::now_utc();
            let renew_threshold =
                expiry - time::Duration::days(config.renew_before_days as i64);

            if now >= renew_threshold {
                let days_until_expiry = (expiry - now).whole_days();
                warn!(
                    target: TARGET,
                    "Certificate expires in {} days, renewal needed",
                    days_until_expiry
                );
                return true;
            }
        }
        None => {
            warn!(target: TARGET, "Could not parse certificate expiry, forcing renewal");
            return true;
        }
    }

    // Check SANs match current configuration
    let expected = expected_sans(config);
    match parse_cert_sans(&pem_data) {
        Some(current) if current == expected => false,
        Some(current) => {
            warn!(
                target: TARGET,
                "Certificate SANs do not match configuration (current: {:?}, expected: {:?}), renewal needed",
                current,
                expected
            );
            true
        }
        None => {
            warn!(target: TARGET, "Could not parse certificate SANs, forcing renewal");
            true
        }
    }
}

/// Parse the expiry date from a PEM certificate using x509-parser
fn parse_cert_expiry(pem_data: &[u8]) -> Option<OffsetDateTime> {
    // Parse PEM
    let (_, pem) = parse_x509_pem(pem_data).ok()?;

    // Parse X.509 certificate
    let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;

    // Get notAfter timestamp and convert to OffsetDateTime
    let not_after = cert.validity().not_after;
    let timestamp = not_after.timestamp();
    OffsetDateTime::from_unix_timestamp(timestamp).ok()
}

/// Paths for certificate renewal task
#[derive(Clone)]
pub struct CertPaths {
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
}

/// Background task that monitors certificate expiration and renews when needed
pub async fn cert_renewal_task(
    config: SelfSignedCertConfig,
    paths: CertPaths,
    tls: RustlsConfig,
) {
    let check_interval = Duration::from_secs(config.check_interval_secs);
    let mut interval = tokio::time::interval(check_interval);

    info!(
        target: TARGET,
        "Starting certificate renewal monitor (check interval: {}s)",
        config.check_interval_secs
    );

    loop {
        interval.tick().await;

        if cert_needs_renewal(&config, &paths.cert_path, &paths.key_path).await
        {
            match generate_self_signed_cert(
                &config,
                &paths.cert_path,
                &paths.key_path,
            )
            .await
            {
                Ok(()) => {
                    match tls
                        .reload_from_pem_file(&paths.cert_path, &paths.key_path)
                        .await
                    {
                        Ok(()) => {
                            info!(target: TARGET, "Certificate renewed and reloaded successfully");
                        }
                        Err(e) => {
                            error!(target: TARGET, "Failed to reload certificate: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!(target: TARGET, "Failed to generate new certificate: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn test_config(san: Vec<String>) -> SelfSignedCertConfig {
        SelfSignedCertConfig {
            enabled: true,
            common_name: "localhost".to_string(),
            san,
            validity_days: 365,
            renew_before_days: 30,
            check_interval_secs: 3600,
        }
    }

    #[tokio::test]
    async fn cert_renewal_detects_san_changes() {
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();
        let cert_path = cert_file.path().to_path_buf();
        let key_path = key_file.path().to_path_buf();

        // Initial config with two IPs
        let config_a = test_config(vec![
            "127.0.0.1".to_string(),
            "192.168.1.1".to_string(),
        ]);

        generate_self_signed_cert(&config_a, &cert_path, &key_path)
            .await
            .unwrap();

        // Same config should not need renewal
        assert!(
            !cert_needs_renewal(&config_a, &cert_path, &key_path).await,
            "same config should not need renewal"
        );

        // Changing one IP should trigger renewal
        let config_b =
            test_config(vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()]);
        assert!(
            cert_needs_renewal(&config_b, &cert_path, &key_path).await,
            "changed IP should trigger renewal"
        );

        // Removing a SAN should trigger renewal
        let config_c = test_config(vec!["127.0.0.1".to_string()]);
        assert!(
            cert_needs_renewal(&config_c, &cert_path, &key_path).await,
            "removed SAN should trigger renewal"
        );

        // Adding a SAN should trigger renewal
        let config_d = test_config(vec![
            "127.0.0.1".to_string(),
            "192.168.1.1".to_string(),
            "172.16.0.1".to_string(),
        ]);
        assert!(
            cert_needs_renewal(&config_d, &cert_path, &key_path).await,
            "added SAN should trigger renewal"
        );
    }
}
