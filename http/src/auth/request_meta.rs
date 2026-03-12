use ave_bridge::ProxyConfig;
use axum::http::HeaderMap;
use ip_network::IpNetwork;
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMeta {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub fn extract_request_meta(
    headers: &HeaderMap,
    addr: SocketAddr,
    proxy: &ProxyConfig,
) -> RequestMeta {
    RequestMeta {
        ip_address: resolve_client_ip(headers, addr, proxy)
            .map(|ip| ip.to_string()),
        user_agent: headers
            .get("User-Agent")
            .and_then(|value| value.to_str().ok().map(ToOwned::to_owned)),
    }
}

pub fn validate_proxy_config(proxy: &ProxyConfig) -> Result<(), String> {
    let invalid_entries: Vec<String> = proxy
        .trusted_proxies
        .iter()
        .filter(|entry| parse_trusted_proxy(entry).is_none())
        .cloned()
        .collect();

    if invalid_entries.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "invalid trusted_proxies entries: {}",
            invalid_entries.join(", ")
        ))
    }
}

pub fn resolve_client_ip(
    headers: &HeaderMap,
    addr: SocketAddr,
    proxy: &ProxyConfig,
) -> Option<IpAddr> {
    let socket_ip = addr.ip();
    if !is_trusted_proxy(socket_ip, proxy) {
        return Some(socket_ip);
    }

    if proxy.trust_x_forwarded_for
        && let Some(ip) = parse_x_forwarded_for(headers)
    {
        return Some(ip);
    }

    if proxy.trust_x_real_ip
        && let Some(ip) = parse_single_ip_header(headers, "X-Real-IP")
    {
        return Some(ip);
    }

    Some(socket_ip)
}

fn is_trusted_proxy(ip: IpAddr, proxy: &ProxyConfig) -> bool {
    proxy.trusted_proxies.iter().any(|entry| {
        parse_trusted_proxy(entry)
            .map(|network| network.contains(ip))
            .unwrap_or(false)
    })
}

fn parse_trusted_proxy(entry: &str) -> Option<IpNetwork> {
    if let Ok(network) = IpNetwork::from_str(entry) {
        return Some(network);
    }

    IpAddr::from_str(entry)
        .ok()
        .and_then(|ip| IpNetwork::new(ip, max_prefix_for(ip)).ok())
}

const fn max_prefix_for(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn parse_x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("X-Forwarded-For")?.to_str().ok()?;
    value
        .split(',')
        .map(str::trim)
        .find_map(|candidate| IpAddr::from_str(candidate).ok())
}

fn parse_single_ip_header(
    headers: &HeaderMap,
    header_name: &str,
) -> Option<IpAddr> {
    let value = headers.get(header_name)?.to_str().ok()?;
    IpAddr::from_str(value.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_peer_ignores_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.10".parse().unwrap());
        let proxy = ProxyConfig::default();

        let ip = resolve_client_ip(
            &headers,
            "192.0.2.2:1234".parse().unwrap(),
            &proxy,
        );

        assert_eq!(ip, Some("192.0.2.2".parse().unwrap()));
    }

    #[test]
    fn trusted_proxy_uses_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "203.0.113.10, 198.51.100.2".parse().unwrap(),
        );
        let proxy = ProxyConfig {
            trusted_proxies: vec!["192.0.2.0/24".to_string()],
            ..ProxyConfig::default()
        };

        let ip = resolve_client_ip(
            &headers,
            "192.0.2.2:1234".parse().unwrap(),
            &proxy,
        );

        assert_eq!(ip, Some("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn trusted_proxy_falls_back_to_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "203.0.113.11".parse().unwrap());
        let proxy = ProxyConfig {
            trusted_proxies: vec!["192.0.2.2".to_string()],
            trust_x_forwarded_for: false,
            trust_x_real_ip: true,
        };

        let ip = resolve_client_ip(
            &headers,
            "192.0.2.2:1234".parse().unwrap(),
            &proxy,
        );

        assert_eq!(ip, Some("203.0.113.11".parse().unwrap()));
    }

    #[test]
    fn invalid_trusted_proxy_config_is_rejected() {
        let proxy = ProxyConfig {
            trusted_proxies: vec![
                "192.0.2.0/24".to_string(),
                "definitely-not-a-network".to_string(),
            ],
            ..ProxyConfig::default()
        };

        let error = validate_proxy_config(&proxy).unwrap_err();
        assert!(error.contains("definitely-not-a-network"));
    }
}
