use config::Config;
use core::error::Error;
use tracing::error;

pub mod command;
use crate::config::Config as BridgeConfig;

const TARGET_SETTING: &str = "Ave-Bridge-Settings";

pub fn build_config(file: &str) -> Result<BridgeConfig, Error> {
    // file configuration (json, yaml or toml)
    let mut bridge_config = BridgeConfig::default();
    if !file.is_empty() {
        let mut config = Config::builder();

        config = config.add_source(config::File::with_name(file));

        let config = config.build().map_err(|e| {
            let e = format!("Error building config: {}", e);
            error!(TARGET_SETTING, e);
            Error::Bridge(e)
        })?;

        bridge_config = config.try_deserialize().map_err(|e| {
            let e = format!("Error try deserialize config: {}", e);
            error!(TARGET_SETTING, e);
            Error::Bridge(e)
        })?;
    }

    // Mix configurations.
    Ok(bridge_config)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        path::PathBuf,
        time::Duration,
    };

    use ave_common::identity::{HashAlgorithm, KeyPairAlgorithm};
    use core::{
        config::{
            AveDbConfig, ExternalDbConfig, LoggingOutput, LoggingRotation,
            SinkServer,
        },
        subject::sinkdata::SinkTypes,
    };
    use network::{NodeType, RoutingNode};
    use tempfile::TempPath;

    use crate::{config::Config as BridgeConfig, settings::build_config};

    const FULL_TOML: &str = r#"
keys_path = "/custom/keys"
prometheus = "1.2.3.4:3333"

[node]
keypair_algorithm = "Ed25519"
hash_algorithm = "Blake3"
ave_db = "/data/ave.db"
external_db = "/data/ext.db"
contracts_path = "/contracts"
always_accept = true
garbage_collector = 900

[node.network]
node_type = "Addressable"
listen_addresses = ["/ip4/127.0.0.1/tcp/5001", "/ip4/127.0.0.1/tcp/5002"]
external_addresses = ["/ip4/10.0.0.1/tcp/7000"]
boot_nodes = [
    { peer_id = "12D3KooWNode1", address = ["/ip4/1.1.1.1/tcp/1000"] },
    { peer_id = "12D3KooWNode2", address = ["/ip4/2.2.2.2/tcp/2000"] }
]

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

[node.network.memory_limit]
Bytes = 1073741824

[logging]
output = { stdout = false, file = true, api = true }
api_url = "https://example.com/logs"
file_path = "/tmp/my.log"
rotation = "hourly"
max_size = 52428800
max_files = 5

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

[auth.api_key]
default_ttl_seconds = 3600
max_keys_per_user = 20

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
"#;

    const FULL_YAML: &str = r#"
keys_path: /custom/keys
prometheus: 1.2.3.4:3333
node:
  keypair_algorithm: Ed25519
  hash_algorithm: Blake3
  ave_db: /data/ave.db
  external_db: /data/ext.db
  contracts_path: /contracts
  always_accept: true
  garbage_collector: 900
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
    memory_limit:
      Bytes: 1073741824
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
  api_key:
    default_ttl_seconds: 3600
    max_keys_per_user: 20
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
"#;

    const FULL_JSON: &str = r#"
{
  "keys_path": "/custom/keys",
  "prometheus": "1.2.3.4:3333",
  "node": {
    "keypair_algorithm": "Ed25519",
    "hash_algorithm": "Blake3",
    "ave_db": "/data/ave.db",
    "external_db": "/data/ext.db",
    "contracts_path": "/contracts",
    "always_accept": true,
    "garbage_collector": 900,
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
        "interval_request": 42
      },
      "memory_limit": {
        "Bytes": 1073741824
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
    "max_files": 5
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
    "api_key": {
      "default_ttl_seconds": 3600,
      "max_keys_per_user": 20
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
      "cleanup_interval_seconds": 1800
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
    "enable_doc": true
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
        assert_eq!(config.prometheus, "1.2.3.4:3333");

        let node = &config.node;
        assert_eq!(node.keypair_algorithm, KeyPairAlgorithm::Ed25519);
        assert_eq!(node.hash_algorithm, HashAlgorithm::Blake3);
        assert!(node.always_accept);
        assert_eq!(node.contracts_path, PathBuf::from("/contracts"));
        assert_eq!(node.garbage_collector, Duration::from_secs(900));
        assert_eq!(
            node.ave_db,
            AveDbConfig::build(&PathBuf::from("/data/ave.db"))
        );
        assert_eq!(
            node.external_db,
            ExternalDbConfig::build(&PathBuf::from("/data/ext.db"))
        );

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
        match &node.network.memory_limit {
            Some(network::MemoryLimit::Bytes(bytes)) => assert_eq!(*bytes, 1073741824),
            _ => panic!("Expected Some(Bytes) variant for memory_limit"),
        }

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
        assert_eq!(auth.database_path, PathBuf::from("/var/db/auth.db"));
        assert_eq!(auth.superadmin, "admin:supersecret");
        assert_eq!(auth.api_key.default_ttl_seconds, 3600);
        assert_eq!(auth.api_key.max_keys_per_user, 20);
        assert_eq!(auth.lockout.max_attempts, 3);
        assert_eq!(auth.lockout.duration_seconds, 600);
        assert!(!auth.rate_limit.enable);
        assert_eq!(auth.rate_limit.window_seconds, 120);
        assert_eq!(auth.rate_limit.max_requests, 50);
        assert!(!auth.rate_limit.limit_by_key);
        assert!(auth.rate_limit.limit_by_ip);
        assert_eq!(auth.rate_limit.cleanup_interval_seconds, 1800);
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
    }

    fn assert_partial_defaults(config: BridgeConfig) {
        assert_eq!(config.keys_path, PathBuf::from("/partial/keys"));
        assert_eq!(config.prometheus, "0.0.0.0:3050");
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
        assert_eq!(config.node.ave_db, AveDbConfig::default());
        assert_eq!(config.node.external_db, ExternalDbConfig::default());
        assert_eq!(config.node.garbage_collector, Duration::from_secs(120));
        assert_eq!(config.node.network.node_type, NodeType::Bootstrap);
        assert!(config.node.network.listen_addresses.is_empty());
        assert!(config.node.network.external_addresses.is_empty());
        assert!(config.node.network.boot_nodes.is_empty());
        assert_eq!(
            config.node.network.control_list.get_interval_request(),
            Duration::from_secs(60)
        );
        assert!(config.node.network.memory_limit.is_none());
    }
}
