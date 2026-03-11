use config::Config;
use std::collections::HashSet;
use tracing::{error, warn};

pub mod command;
use crate::config::Config as BridgeConfig;
use crate::error::BridgeError;

pub fn build_config(file: &str) -> Result<BridgeConfig, BridgeError> {
    // file configuration (json, yaml or toml)
    let bridge_config = if !file.is_empty() {
        let mut config = Config::builder();

        config = config.add_source(config::File::with_name(file));

        let config = config.build().map_err(|e| {
            error!(file = %file, error = %e, "Failed to build configuration");
            BridgeError::ConfigBuild(e.to_string())
        })?;

        config.try_deserialize().map_err(|e| {
            error!(file = %file, error = %e, "Failed to deserialize configuration");
            BridgeError::ConfigDeserialize(e.to_string())
        })?
    } else {
        BridgeConfig::default()
    };

    // Validate HTTPS configuration
    validate_https_config(&bridge_config)?;

    // Validate network configuration
    validate_network_config(&bridge_config)?;

    // Mix configurations.
    Ok(bridge_config)
}

/// Validate network configuration
fn validate_network_config(config: &BridgeConfig) -> Result<(), BridgeError> {
    let network = &config.node.network;

    network.memory_limits.validate().map_err(|e| {
        error!(error = %e, "Invalid network configuration");
        BridgeError::ConfigBuild(e)
    })?;

    if network.max_app_message_bytes == 0 {
        let msg =
            "network.max_app_message_bytes must be greater than 0".to_owned();
        error!(error = %msg, "Invalid network configuration");
        return Err(BridgeError::ConfigBuild(msg));
    }

    if network.max_pending_outbound_bytes_per_peer > 0
        && network.max_pending_outbound_bytes_per_peer
            < network.max_app_message_bytes
    {
        let msg = format!(
            "network.max_pending_outbound_bytes_per_peer ({}) must be >= network.max_app_message_bytes ({})",
            network.max_pending_outbound_bytes_per_peer,
            network.max_app_message_bytes
        );
        error!(error = %msg, "Invalid network configuration");
        return Err(BridgeError::ConfigBuild(msg));
    }

    if network.max_pending_inbound_bytes_per_peer > 0
        && network.max_pending_inbound_bytes_per_peer
            < network.max_app_message_bytes
    {
        let msg = format!(
            "network.max_pending_inbound_bytes_per_peer ({}) must be >= network.max_app_message_bytes ({})",
            network.max_pending_inbound_bytes_per_peer,
            network.max_app_message_bytes
        );
        error!(error = %msg, "Invalid network configuration");
        return Err(BridgeError::ConfigBuild(msg));
    }

    if network.max_pending_outbound_bytes_total > 0
        && network.max_pending_outbound_bytes_total < network.max_app_message_bytes
    {
        let msg = format!(
            "network.max_pending_outbound_bytes_total ({}) must be >= network.max_app_message_bytes ({})",
            network.max_pending_outbound_bytes_total,
            network.max_app_message_bytes
        );
        error!(error = %msg, "Invalid network configuration");
        return Err(BridgeError::ConfigBuild(msg));
    }

    if network.max_pending_inbound_bytes_total > 0
        && network.max_pending_inbound_bytes_total < network.max_app_message_bytes
    {
        let msg = format!(
            "network.max_pending_inbound_bytes_total ({}) must be >= network.max_app_message_bytes ({})",
            network.max_pending_inbound_bytes_total,
            network.max_app_message_bytes
        );
        error!(error = %msg, "Invalid network configuration");
        return Err(BridgeError::ConfigBuild(msg));
    }

    for addr in &network.listen_addresses {
        if addr.trim().is_empty() {
            let msg =
                "network.listen_addresses contains an empty address".to_owned();
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }
    }

    for addr in &network.external_addresses {
        if addr.trim().is_empty() {
            let msg = "network.external_addresses contains an empty address"
                .to_owned();
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }
    }

    for (index, node) in network.boot_nodes.iter().enumerate() {
        if node.peer_id.trim().is_empty() {
            let msg = format!("network.boot_nodes[{index}].peer_id is empty");
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }
        if node.address.is_empty() {
            let msg = format!(
                "network.boot_nodes[{index}] must contain at least one address"
            );
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }
        if node.address.iter().any(|addr| addr.trim().is_empty()) {
            let msg = format!(
                "network.boot_nodes[{index}] contains an empty address"
            );
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }
    }

    let control_list = &network.control_list;
    if control_list.get_interval_request().is_zero() {
        let msg =
            "network.control_list.interval_request must be greater than 0"
                .to_owned();
        error!(error = %msg, "Invalid network configuration");
        return Err(BridgeError::ConfigBuild(msg));
    }

    if control_list.get_request_timeout().is_zero() {
        let msg = "network.control_list.request_timeout must be greater than 0"
            .to_owned();
        error!(error = %msg, "Invalid network configuration");
        return Err(BridgeError::ConfigBuild(msg));
    }

    if control_list.get_request_timeout() > control_list.get_interval_request()
    {
        let msg = format!(
            "network.control_list.request_timeout ({:?}) must be <= network.control_list.interval_request ({:?})",
            control_list.get_request_timeout(),
            control_list.get_interval_request()
        );
        error!(error = %msg, "Invalid network configuration");
        return Err(BridgeError::ConfigBuild(msg));
    }

    // `max_concurrent_requests = 0` is accepted and normalized at runtime to 1
    // (see network/utils.rs request_peer_lists buffer_unordered max(1)).

    for service in control_list.get_service_allow_list() {
        if !(service.starts_with("http://") || service.starts_with("https://"))
        {
            let msg = format!(
                "network.control_list.service_allow_list contains an invalid URL: {service}"
            );
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }
    }

    for service in control_list.get_service_block_list() {
        if !(service.starts_with("http://") || service.starts_with("https://"))
        {
            let msg = format!(
                "network.control_list.service_block_list contains an invalid URL: {service}"
            );
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }
    }

    if control_list.get_enable() {
        let has_allow_source = !control_list.get_allow_list().is_empty()
            || !control_list.get_service_allow_list().is_empty()
            || !network.boot_nodes.is_empty();
        if !has_allow_source {
            let msg = "network.control_list.enable is true but there are no allow sources (allow_list, service_allow_list or boot_nodes)".to_owned();
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }

        let allow: HashSet<String> = control_list
            .get_allow_list()
            .into_iter()
            .map(|peer| peer.trim().to_owned())
            .collect();
        let block: HashSet<String> = control_list
            .get_block_list()
            .into_iter()
            .map(|peer| peer.trim().to_owned())
            .collect();
        if let Some(peer) = allow.intersection(&block).next() {
            let msg = format!(
                "network.control_list has peer present in both allow_list and block_list: {peer}"
            );
            error!(error = %msg, "Invalid network configuration");
            return Err(BridgeError::ConfigBuild(msg));
        }
    }

    Ok(())
}

/// Validate HTTPS configuration consistency
fn validate_https_config(config: &BridgeConfig) -> Result<(), BridgeError> {
    let http = &config.http;

    if http.https_address.is_some()
        && (http.https_cert_path.is_none()
            || http.https_private_key_path.is_none())
    {
        let msg = "HTTPS is enabled (https_address is set) but https_cert_path \
                   and/or https_private_key_path are missing";
        error!(error = %msg, "Invalid HTTPS configuration");
        return Err(BridgeError::ConfigBuild(msg.to_owned()));
    }

    if http.self_signed_cert.enabled && http.https_address.is_none() {
        warn!(
            "self_signed_cert.enabled is true but https_address is not set, \
             self-signed certificates will not be used"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::PathBuf,
        time::Duration,
    };

    use ave_common::identity::{HashAlgorithm, KeyPairAlgorithm};
    use ave_core::{
        config::{
            AveExternalDBFeatureConfig, AveInternalDBFeatureConfig,
            LoggingOutput, LoggingRotation, MachineSpec, SinkServer,
        },
        subject::sinkdata::SinkTypes,
    };
    use network::{MemoryLimitsConfig, NodeType, RoutingNode};
    use tempfile::TempPath;

    use crate::{
        config::Config as BridgeConfig, error::BridgeError,
        settings::build_config,
    };

    const FULL_TOML: &str = r#"
keys_path = "/custom/keys"

[node]
keypair_algorithm = "Ed25519"
hash_algorithm = "Blake3"
contracts_path = "/contracts"
always_accept = true
tracking_size = 200
is_service = true

[node.internal_db]
db = "/data/ave.db"
durability = true

[node.external_db]
db = "/data/ext.db"
durability = true

[node.spec]
custom = { ram_mb = 2048, cpu_cores = 4 }

[node.network]
node_type = "Addressable"
listen_addresses = ["/ip4/127.0.0.1/tcp/5001", "/ip4/127.0.0.1/tcp/5002"]
external_addresses = ["/ip4/10.0.0.1/tcp/7000"]
boot_nodes = [
    { peer_id = "12D3KooWNode1", address = ["/ip4/1.1.1.1/tcp/1000"] },
    { peer_id = "12D3KooWNode2", address = ["/ip4/2.2.2.2/tcp/2000"] }
]
max_app_message_bytes = 2097152
max_pending_outbound_bytes_per_peer = 16777216
max_pending_inbound_bytes_per_peer = 8388608
max_pending_outbound_bytes_total = 33554432
max_pending_inbound_bytes_total = 25165824

[node.network.routing]
dht_random_walk = false
discovery_only_if_under_num = 25
allow_private_address_in_dht = true
allow_dns_address_in_dht = true
allow_loop_back_address_in_dht = true
kademlia_disjoint_query_paths = false

[node.network.control_list]
enable = true
allow_list = ["Peer200", "Peer300"]
block_list = ["Peer1", "Peer2"]
service_allow_list = ["http://allow.local/list"]
service_block_list = ["http://block.local/list"]
interval_request = 42
request_timeout = 7
max_concurrent_requests = 16

[node.network.memory_limits]
type = "percentage"
value = 0.8

[logging]
output = { stdout = false, file = true, api = true }
api_url = "https://example.com/logs"
file_path = "/tmp/my.log"
rotation = "hourly"
max_size = 52428800
max_files = 5
level = "debug"

[sink]
auth = "https://auth.service"
username = "sink-user"

[sink.sinks]
primary = [
    { server = "SinkOne", events = ["Create", "All"], url = "https://sink.one", auth = true },
    { server = "SinkTwo", events = ["Transfer"], url = "https://sink.two", auth = false }
]

[auth]
enable = true
database_path = "/var/db/auth.db"
superadmin = "admin:supersecret"
durability = true

[auth.api_key]
default_ttl_seconds = 3600
max_keys_per_user = 20
prefix = "custom_prefix_"

[auth.lockout]
max_attempts = 3
duration_seconds = 600

[auth.rate_limit]
enable = false
window_seconds = 120
max_requests = 50
limit_by_key = false
limit_by_ip = true
cleanup_interval_seconds = 1800

[[auth.rate_limit.sensitive_endpoints]]
endpoint = "/login"
max_requests = 5
window_seconds = 30

[auth.session]
audit_enable = false
audit_retention_days = 30
audit_max_entries = 1000000

[http]
http_address = "127.0.0.1:4000"
https_address = "127.0.0.1:4443"
https_cert_path = "/certs/cert.pem"
https_private_key_path = "/certs/key.pem"
enable_doc = true

[http.proxy]
trusted_proxies = ["10.0.0.1"]
trust_x_forwarded_for = false
trust_x_real_ip = false

[http.cors]
enabled = false
allow_any_origin = false
allowed_origins = ["https://app.example.com"]
allow_credentials = true

[http.self_signed_cert]
enabled = true
common_name = "localhost"
san = ["127.0.0.1", "::1"]
validity_days = 365
renew_before_days = 30
check_interval_secs = 3600
"#;

    const FULL_YAML: &str = r#"
keys_path: /custom/keys
node:
  keypair_algorithm: Ed25519
  hash_algorithm: Blake3
  internal_db:
    db: /data/ave.db
    durability: true
  external_db:
    db: /data/ext.db
    durability: true
  spec:
    custom:
      ram_mb: 2048
      cpu_cores: 4
  contracts_path: /contracts
  always_accept: true
  tracking_size: 200
  is_service: true
  network:
    node_type: Addressable
    listen_addresses:
      - /ip4/127.0.0.1/tcp/5001
      - /ip4/127.0.0.1/tcp/5002
    external_addresses:
      - /ip4/10.0.0.1/tcp/7000
    boot_nodes:
      - peer_id: 12D3KooWNode1
        address:
          - /ip4/1.1.1.1/tcp/1000
      - peer_id: 12D3KooWNode2
        address:
          - /ip4/2.2.2.2/tcp/2000
    max_app_message_bytes: 2097152
    max_pending_outbound_bytes_per_peer: 16777216
    max_pending_inbound_bytes_per_peer: 8388608
    max_pending_outbound_bytes_total: 33554432
    max_pending_inbound_bytes_total: 25165824
    routing:
      dht_random_walk: false
      discovery_only_if_under_num: 25
      allow_private_address_in_dht: true
      allow_dns_address_in_dht: true
      allow_loop_back_address_in_dht: true
      kademlia_disjoint_query_paths: false
    control_list:
      enable: true
      allow_list: [Peer200, Peer300]
      block_list: [Peer1, Peer2]
      service_allow_list: [http://allow.local/list]
      service_block_list: [http://block.local/list]
      interval_request: 42
      request_timeout: 7
      max_concurrent_requests: 16
    memory_limits:
      type: percentage
      value: 0.8
logging:
  output:
    stdout: false
    file: true
    api: true
  api_url: https://example.com/logs
  file_path: /tmp/my.log
  rotation: hourly
  max_size: 52428800
  max_files: 5
  level: debug
sink:
  auth: https://auth.service
  username: sink-user
  sinks:
    primary:
      - server: SinkOne
        events: [Create, All]
        url: https://sink.one
        auth: true
      - server: SinkTwo
        events: [Transfer]
        url: https://sink.two
        auth: false
auth:
  enable: true
  database_path: /var/db/auth.db
  superadmin: admin:supersecret
  durability: true
  api_key:
    default_ttl_seconds: 3600
    max_keys_per_user: 20
    prefix: custom_prefix_
  lockout:
    max_attempts: 3
    duration_seconds: 600
  rate_limit:
    enable: false
    window_seconds: 120
    max_requests: 50
    limit_by_key: false
    limit_by_ip: true
    cleanup_interval_seconds: 1800
    sensitive_endpoints:
      - endpoint: /login
        max_requests: 5
        window_seconds: 30
  session:
    audit_enable: false
    audit_retention_days: 30
    audit_max_entries: 1000000
http:
  http_address: 127.0.0.1:4000
  https_address: 127.0.0.1:4443
  https_cert_path: /certs/cert.pem
  https_private_key_path: /certs/key.pem
  enable_doc: true
  proxy:
    trusted_proxies:
      - 10.0.0.1
    trust_x_forwarded_for: false
    trust_x_real_ip: false
  cors:
    enabled: false
    allow_any_origin: false
    allowed_origins:
      - https://app.example.com
    allow_credentials: true
  self_signed_cert:
    enabled: true
    common_name: localhost
    san:
      - "127.0.0.1"
      - "::1"
    validity_days: 365
    renew_before_days: 30
    check_interval_secs: 3600
"#;

    const FULL_JSON: &str = r#"
{
  "keys_path": "/custom/keys",
  "node": {
    "keypair_algorithm": "Ed25519",
    "hash_algorithm": "Blake3",
    "internal_db": {
      "db": "/data/ave.db",
      "durability": true
    },
    "external_db": {
      "db": "/data/ext.db",
      "durability": true
    },
    "spec": {
      "custom": {
        "ram_mb": 2048,
        "cpu_cores": 4
      }
    },
    "contracts_path": "/contracts",
    "always_accept": true,
    "tracking_size": 200,
    "is_service": true,
    "network": {
      "node_type": "Addressable",
      "listen_addresses": [
        "/ip4/127.0.0.1/tcp/5001",
        "/ip4/127.0.0.1/tcp/5002"
      ],
      "external_addresses": [
        "/ip4/10.0.0.1/tcp/7000"
      ],
      "boot_nodes": [
        {
          "peer_id": "12D3KooWNode1",
          "address": ["/ip4/1.1.1.1/tcp/1000"]
        },
        {
          "peer_id": "12D3KooWNode2",
          "address": ["/ip4/2.2.2.2/tcp/2000"]
        }
      ],
      "max_app_message_bytes": 2097152,
      "max_pending_outbound_bytes_per_peer": 16777216,
      "max_pending_inbound_bytes_per_peer": 8388608,
      "max_pending_outbound_bytes_total": 33554432,
      "max_pending_inbound_bytes_total": 25165824,
      "routing": {
        "dht_random_walk": false,
        "discovery_only_if_under_num": 25,
        "allow_private_address_in_dht": true,
        "allow_dns_address_in_dht": true,
        "allow_loop_back_address_in_dht": true,
        "kademlia_disjoint_query_paths": false
      },
      "control_list": {
        "enable": true,
        "allow_list": ["Peer200", "Peer300"],
        "block_list": ["Peer1", "Peer2"],
        "service_allow_list": ["http://allow.local/list"],
        "service_block_list": ["http://block.local/list"],
        "interval_request": 42,
        "request_timeout": 7,
        "max_concurrent_requests": 16
      },
      "memory_limits": {
        "type": "percentage",
        "value": 0.8
      }
    }
  },
  "logging": {
    "output": {
      "stdout": false,
      "file": true,
      "api": true
    },
    "api_url": "https://example.com/logs",
    "file_path": "/tmp/my.log",
    "rotation": "hourly",
    "max_size": 52428800,
    "max_files": 5,
    "level": "debug"
  },
  "sink": {
    "auth": "https://auth.service",
    "username": "sink-user",
    "sinks": {
      "primary": [
        {
          "server": "SinkOne",
          "events": ["Create", "All"],
          "url": "https://sink.one",
          "auth": true
        },
        {
          "server": "SinkTwo",
          "events": ["Transfer"],
          "url": "https://sink.two",
          "auth": false
        }
      ]
    }
  },
  "auth": {
    "enable": true,
    "database_path": "/var/db/auth.db",
    "superadmin": "admin:supersecret",
    "durability": true,
    "api_key": {
      "default_ttl_seconds": 3600,
      "max_keys_per_user": 20,
      "prefix": "custom_prefix_"
    },
    "lockout": {
      "max_attempts": 3,
      "duration_seconds": 600
    },
    "rate_limit": {
      "enable": false,
      "window_seconds": 120,
      "max_requests": 50,
      "limit_by_key": false,
      "limit_by_ip": true,
      "cleanup_interval_seconds": 1800,
      "sensitive_endpoints": [
        { "endpoint": "/login", "max_requests": 5, "window_seconds": 30 }
      ]
    },
    "session": {
      "audit_enable": false,
      "audit_retention_days": 30,
      "audit_max_entries": 1000000
    }
  },
  "http": {
    "http_address": "127.0.0.1:4000",
    "https_address": "127.0.0.1:4443",
    "https_cert_path": "/certs/cert.pem",
    "https_private_key_path": "/certs/key.pem",
    "enable_doc": true,
    "proxy": {
      "trusted_proxies": ["10.0.0.1"],
      "trust_x_forwarded_for": false,
      "trust_x_real_ip": false
    },
    "cors": {
      "enabled": false,
      "allow_any_origin": false,
      "allowed_origins": ["https://app.example.com"],
      "allow_credentials": true
    },
    "self_signed_cert": {
      "enabled": true,
      "common_name": "localhost",
      "san": ["127.0.0.1", "::1"],
      "validity_days": 365,
      "renew_before_days": 30,
      "check_interval_secs": 3600
    }
  }
}
"#;

    const PARTIAL_TOML: &str = r#"
keys_path = "/partial/keys"

[auth]
enable = true

[http]
http_address = "127.0.0.1:8888"
enable_doc = true
"#;

    const PARTIAL_YAML: &str = r#"
keys_path: /partial/keys
auth:
  enable: true
http:
  http_address: 127.0.0.1:8888
  enable_doc: true
"#;

    const PARTIAL_JSON: &str = r#"
{
  "keys_path": "/partial/keys",
  "auth": {
    "enable": true
  },
  "http": {
    "http_address": "127.0.0.1:8888",
    "enable_doc": true
  }
}
"#;

    #[test]
    fn build_config_reads_full_toml() {
        let path = write_config("toml", FULL_TOML);
        let config = build_config(path.to_str().unwrap()).expect("toml config");
        assert_full_config(config);
    }

    #[test]
    fn build_config_reads_full_yaml() {
        let path = write_config("yaml", FULL_YAML);
        let config = build_config(path.to_str().unwrap()).expect("yaml config");
        assert_full_config(config);
    }

    #[test]
    fn build_config_reads_full_json() {
        let path = write_config("json", FULL_JSON);
        let config = build_config(path.to_str().unwrap()).expect("json config");
        assert_full_config(config);
    }

    #[test]
    fn build_config_fills_defaults_for_partial_toml() {
        let path = write_config("toml", PARTIAL_TOML);
        let config =
            build_config(path.to_str().unwrap()).expect("partial toml config");
        assert_partial_defaults(config);
    }

    #[test]
    fn build_config_fills_defaults_for_partial_yaml() {
        let path = write_config("yaml", PARTIAL_YAML);
        let config =
            build_config(path.to_str().unwrap()).expect("partial yaml config");
        assert_partial_defaults(config);
    }

    #[test]
    fn build_config_fills_defaults_for_partial_json() {
        let path = write_config("json", PARTIAL_JSON);
        let config =
            build_config(path.to_str().unwrap()).expect("partial json config");
        assert_partial_defaults(config);
    }

    fn write_config(extension: &str, content: &str) -> TempPath {
        let file = tempfile::Builder::new()
            .suffix(&format!(".{extension}"))
            .tempfile()
            .expect("create temp config file");
        std::fs::write(file.path(), content).expect("write temp config");
        file.into_temp_path()
    }

    fn assert_full_config(config: BridgeConfig) {
        assert_eq!(config.keys_path, PathBuf::from("/custom/keys"));

        let node = &config.node;
        assert_eq!(node.keypair_algorithm, KeyPairAlgorithm::Ed25519);
        assert_eq!(node.hash_algorithm, HashAlgorithm::Blake3);
        assert!(node.always_accept);
        assert_eq!(node.contracts_path, PathBuf::from("/contracts"));
        assert_eq!(node.tracking_size, 200);
        assert!(node.is_service);
        assert_eq!(
            node.internal_db.db,
            AveInternalDBFeatureConfig::build(&PathBuf::from("/data/ave.db"))
        );

        assert!(node.internal_db.durability);
        match &node.spec {
            Some(MachineSpec::Custom { ram_mb, cpu_cores }) => {
                assert_eq!(*ram_mb, 2048);
                assert_eq!(*cpu_cores, 4);
            }
            _ => panic!("Expected MachineSpec::Custom"),
        }
        assert_eq!(
            node.external_db.db,
            AveExternalDBFeatureConfig::build(&PathBuf::from("/data/ext.db"))
        );
        assert!(node.external_db.durability);

        assert_eq!(node.network.node_type, NodeType::Addressable);
        assert_eq!(
            node.network.listen_addresses,
            vec![
                "/ip4/127.0.0.1/tcp/5001".to_owned(),
                "/ip4/127.0.0.1/tcp/5002".to_owned()
            ]
        );
        assert_eq!(
            node.network.external_addresses,
            vec!["/ip4/10.0.0.1/tcp/7000".to_owned()]
        );
        let expected_boot_nodes = vec![
            RoutingNode {
                peer_id: "12D3KooWNode1".to_owned(),
                address: vec!["/ip4/1.1.1.1/tcp/1000".to_owned()],
            },
            RoutingNode {
                peer_id: "12D3KooWNode2".to_owned(),
                address: vec!["/ip4/2.2.2.2/tcp/2000".to_owned()],
            },
        ];
        assert_eq!(node.network.boot_nodes.len(), expected_boot_nodes.len());
        for expected in expected_boot_nodes {
            let Some(actual) = node
                .network
                .boot_nodes
                .iter()
                .find(|node| node.peer_id == expected.peer_id)
            else {
                panic!("boot node {} missing", expected.peer_id);
            };
            assert_eq!(actual.address, expected.address);
        }
        assert!(!node.network.routing.get_dht_random_walk());
        assert_eq!(node.network.routing.get_discovery_limit(), 25);
        assert!(node.network.routing.get_allow_private_address_in_dht());
        assert!(node.network.routing.get_allow_dns_address_in_dht());
        assert!(node.network.routing.get_allow_loop_back_address_in_dht());
        assert!(!node.network.routing.get_kademlia_disjoint_query_paths());
        assert!(node.network.control_list.get_enable());
        assert_eq!(
            node.network.control_list.get_allow_list(),
            vec!["Peer200", "Peer300"]
        );
        assert_eq!(
            node.network.control_list.get_block_list(),
            vec!["Peer1", "Peer2"]
        );
        assert_eq!(
            node.network.control_list.get_service_allow_list(),
            vec!["http://allow.local/list"]
        );
        assert_eq!(
            node.network.control_list.get_service_block_list(),
            vec!["http://block.local/list"]
        );
        assert_eq!(
            node.network.control_list.get_interval_request(),
            Duration::from_secs(42)
        );
        assert_eq!(
            node.network.control_list.get_request_timeout(),
            Duration::from_secs(7)
        );
        assert_eq!(node.network.control_list.get_max_concurrent_requests(), 16);
        assert_eq!(
            node.network.memory_limits,
            MemoryLimitsConfig::Percentage { value: 0.8 }
        );
        assert_eq!(node.network.max_app_message_bytes, 2097152);
        assert_eq!(node.network.max_pending_outbound_bytes_per_peer, 16777216);
        assert_eq!(node.network.max_pending_inbound_bytes_per_peer, 8388608);
        assert_eq!(node.network.max_pending_outbound_bytes_total, 33554432);
        assert_eq!(node.network.max_pending_inbound_bytes_total, 25165824);
        let logging = &config.logging;
        assert_eq!(
            logging.output,
            LoggingOutput {
                stdout: false,
                file: true,
                api: true
            }
        );
        assert_eq!(
            logging.api_url.as_deref(),
            Some("https://example.com/logs")
        );
        assert_eq!(logging.file_path, PathBuf::from("/tmp/my.log"));
        assert_eq!(logging.rotation, LoggingRotation::Hourly);
        assert_eq!(logging.max_size, 52_428_800);
        assert_eq!(logging.max_files, 5);
        assert_eq!(logging.level, "debug");

        let mut expected_sinks = BTreeMap::new();
        expected_sinks.insert(
            "primary".to_owned(),
            vec![
                SinkServer {
                    server: "SinkOne".to_owned(),
                    events: BTreeSet::from([SinkTypes::All, SinkTypes::Create]),
                    url: "https://sink.one".to_owned(),
                    auth: true,
                },
                SinkServer {
                    server: "SinkTwo".to_owned(),
                    events: BTreeSet::from([SinkTypes::Transfer]),
                    url: "https://sink.two".to_owned(),
                    auth: false,
                },
            ],
        );
        assert_eq!(config.sink.sinks, expected_sinks);
        assert_eq!(config.sink.auth, "https://auth.service");
        assert_eq!(config.sink.username, "sink-user");

        let auth = &config.auth;
        assert!(auth.enable);
        assert!(auth.durability);
        assert_eq!(auth.database_path, PathBuf::from("/var/db/auth.db"));
        assert_eq!(auth.superadmin, "admin:supersecret");
        assert_eq!(auth.api_key.default_ttl_seconds, 3600);
        assert_eq!(auth.api_key.max_keys_per_user, 20);
        assert_eq!(auth.api_key.prefix, "custom_prefix_");
        assert_eq!(auth.lockout.max_attempts, 3);
        assert_eq!(auth.lockout.duration_seconds, 600);
        assert!(!auth.rate_limit.enable);
        assert_eq!(auth.rate_limit.window_seconds, 120);
        assert_eq!(auth.rate_limit.max_requests, 50);
        assert!(!auth.rate_limit.limit_by_key);
        assert!(auth.rate_limit.limit_by_ip);
        assert_eq!(auth.rate_limit.cleanup_interval_seconds, 1800);
        assert_eq!(auth.rate_limit.sensitive_endpoints.len(), 1);
        assert_eq!(auth.rate_limit.sensitive_endpoints[0].endpoint, "/login");
        assert_eq!(auth.rate_limit.sensitive_endpoints[0].max_requests, 5);
        assert_eq!(
            auth.rate_limit.sensitive_endpoints[0].window_seconds,
            Some(30)
        );
        assert!(!auth.session.audit_enable);
        assert_eq!(auth.session.audit_retention_days, 30);
        assert_eq!(auth.session.audit_max_entries, 1_000_000);

        let http = &config.http;
        assert_eq!(http.http_address, "127.0.0.1:4000");
        assert_eq!(http.https_address.as_deref(), Some("127.0.0.1:4443"));
        assert_eq!(
            http.https_cert_path.as_deref(),
            Some(PathBuf::from("/certs/cert.pem").as_path())
        );
        assert_eq!(
            http.https_private_key_path.as_deref(),
            Some(PathBuf::from("/certs/key.pem").as_path())
        );
        assert!(http.enable_doc);
        assert_eq!(http.proxy.trusted_proxies, vec!["10.0.0.1".to_owned()]);
        assert!(!http.proxy.trust_x_forwarded_for);
        assert!(!http.proxy.trust_x_real_ip);
        assert!(!http.cors.enabled);
        assert!(!http.cors.allow_any_origin);
        assert_eq!(http.cors.allowed_origins, vec!["https://app.example.com"]);
        assert!(http.cors.allow_credentials);
        assert!(http.self_signed_cert.enabled);
        assert_eq!(http.self_signed_cert.common_name, "localhost");
        assert_eq!(
            http.self_signed_cert.san,
            vec!["127.0.0.1".to_owned(), "::1".to_owned()]
        );
        assert_eq!(http.self_signed_cert.validity_days, 365);
        assert_eq!(http.self_signed_cert.renew_before_days, 30);
        assert_eq!(http.self_signed_cert.check_interval_secs, 3600);
    }

    fn assert_partial_defaults(config: BridgeConfig) {
        assert_eq!(config.keys_path, PathBuf::from("/partial/keys"));
        assert!(config.auth.enable);
        assert_eq!(config.http.http_address, "127.0.0.1:8888");
        assert!(config.http.enable_doc);

        // Defaults remain for everything not provided.
        assert_eq!(config.logging.output.stdout, true);
        assert_eq!(config.logging.output.file, false);
        assert_eq!(config.logging.rotation, LoggingRotation::Size);
        assert_eq!(config.logging.file_path, PathBuf::from("logs"));
        assert_eq!(config.logging.max_files, 3);
        assert_eq!(config.sink.sinks.len(), 0);

        assert_eq!(config.node.keypair_algorithm, KeyPairAlgorithm::Ed25519);
        assert_eq!(config.node.hash_algorithm, HashAlgorithm::Blake3);
        assert_eq!(config.node.contracts_path, PathBuf::new());
        assert_eq!(
            config.node.internal_db.db,
            AveInternalDBFeatureConfig::default()
        );
        assert_eq!(
            config.node.external_db.db,
            AveExternalDBFeatureConfig::default()
        );
        assert_eq!(config.node.tracking_size, 100);
        assert!(!config.node.is_service);
        assert_eq!(config.node.network.node_type, NodeType::Bootstrap);
        assert!(config.node.network.listen_addresses.is_empty());
        assert!(config.node.network.external_addresses.is_empty());
        assert!(config.node.network.boot_nodes.is_empty());
        assert_eq!(
            config.node.network.control_list.get_interval_request(),
            Duration::from_secs(60)
        );
        assert_eq!(
            config.node.network.control_list.get_request_timeout(),
            Duration::from_secs(5)
        );
        assert_eq!(
            config
                .node
                .network
                .control_list
                .get_max_concurrent_requests(),
            8
        );
        assert_eq!(config.node.network.max_app_message_bytes, 1024 * 1024);
        assert_eq!(
            config.node.network.max_pending_outbound_bytes_per_peer,
            8 * 1024 * 1024
        );
        assert_eq!(
            config.node.network.max_pending_inbound_bytes_per_peer,
            8 * 1024 * 1024
        );
        assert_eq!(config.node.network.max_pending_outbound_bytes_total, 0);
        assert_eq!(config.node.network.max_pending_inbound_bytes_total, 0);
        assert!(config.node.spec.is_none());

        // node defaults
        assert!(!config.node.always_accept);
        assert!(!config.node.internal_db.durability);
        assert!(!config.node.external_db.durability);
        assert_eq!(
            config.node.network.memory_limits,
            MemoryLimitsConfig::Disabled
        );

        // auth defaults
        assert!(!config.auth.durability);
        assert_eq!(config.auth.api_key.prefix, "ave_node_");

        // http.cors defaults
        assert!(config.http.cors.enabled);
        assert!(config.http.cors.allow_any_origin);
        assert!(config.http.cors.allowed_origins.is_empty());
        assert!(!config.http.cors.allow_credentials);

        // http.proxy defaults
        assert!(config.http.proxy.trusted_proxies.is_empty());
        assert!(config.http.proxy.trust_x_forwarded_for);
        assert!(config.http.proxy.trust_x_real_ip);

        // http.self_signed_cert defaults
        assert!(!config.http.self_signed_cert.enabled);
        assert_eq!(config.http.self_signed_cert.common_name, "localhost");
        assert_eq!(
            config.http.self_signed_cert.san,
            vec!["127.0.0.1".to_owned(), "::1".to_owned()]
        );
        assert_eq!(config.http.self_signed_cert.validity_days, 365);
        assert_eq!(config.http.self_signed_cert.renew_before_days, 30);
        assert_eq!(config.http.self_signed_cert.check_interval_secs, 3600);
    }

    #[test]
    fn build_config_rejects_invalid_network_memory_limits() {
        const INVALID_TOML: &str = r#"
        [node.network.memory_limits]
        type = "percentage"
        value = 2.0
        "#;

        let path = write_config("toml", INVALID_TOML);
        let err =
            build_config(path.to_str().unwrap()).expect_err("invalid config");

        match err {
            BridgeError::ConfigBuild(msg) => {
                assert!(msg.contains("network.memory_limits percentage"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn build_config_rejects_invalid_network_message_limits() {
        const INVALID_TOML: &str = r#"
        [node.network]
        max_app_message_bytes = 0
        "#;

        let path = write_config("toml", INVALID_TOML);
        let err =
            build_config(path.to_str().unwrap()).expect_err("invalid config");

        match err {
            BridgeError::ConfigBuild(msg) => {
                assert!(msg.contains("max_app_message_bytes"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn build_config_rejects_invalid_control_list_timeout() {
        const INVALID_TOML: &str = r#"
        [node.network.control_list]
        interval_request = 30
        request_timeout = 40
        "#;

        let path = write_config("toml", INVALID_TOML);
        let err =
            build_config(path.to_str().unwrap()).expect_err("invalid config");

        match err {
            BridgeError::ConfigBuild(msg) => {
                assert!(msg.contains("request_timeout"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn build_config_allows_zero_control_list_max_concurrency() {
        const ZERO_TOML: &str = r#"
        [node.network.control_list]
        max_concurrent_requests = 0
        "#;

        let path = write_config("toml", ZERO_TOML);
        let config = build_config(path.to_str().unwrap())
            .expect("zero max_concurrent_requests should be accepted");
        assert_eq!(
            config
                .node
                .network
                .control_list
                .get_max_concurrent_requests(),
            0
        );
    }

    #[test]
    fn build_config_allows_zero_pending_queue_limits() {
        const ZERO_LIMITS_TOML: &str = r#"
        [node.network]
        max_pending_outbound_bytes_per_peer = 0
        max_pending_inbound_bytes_per_peer = 0
        max_pending_outbound_bytes_total = 0
        max_pending_inbound_bytes_total = 0
        "#;

        let path = write_config("toml", ZERO_LIMITS_TOML);
        let config = build_config(path.to_str().unwrap())
            .expect("zero queue limits should be accepted");

        assert_eq!(config.node.network.max_pending_outbound_bytes_per_peer, 0);
        assert_eq!(config.node.network.max_pending_inbound_bytes_per_peer, 0);
        assert_eq!(config.node.network.max_pending_outbound_bytes_total, 0);
        assert_eq!(config.node.network.max_pending_inbound_bytes_total, 0);
    }
}
