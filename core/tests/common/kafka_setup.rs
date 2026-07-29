use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use futures::StreamExt;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::{ClientConfig, Message};
use testcontainers::core::{
    CmdWaitFor, ContainerPort, CopyDataSource, CopyToContainer, ExecCommand,
    Host, WaitFor,
};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, Image, ImageExt};
use tokio::sync::{Semaphore, SemaphorePermit};

use super::test_sink::TestTlsMaterial;

const IMAGE_NAME: &str = "redpandadata/redpanda";
const IMAGE_TAG: &str = "v24.2.7";
const KAFKA_PORT: u16 = 9092;
const ADMIN_API_PORT: u16 = 9644;

/// Redpanda (seastar) reserves ~10_000 AIO events per container while the
/// host limit (`/proc/sys/fs/aio-max-nr`, typically 65_536) fits only ~6.
/// Parallel tests start containers faster than finished ones release their
/// AIO allocation, so under load a container can die at startup. Cap
/// concurrent containers at 3 (~30_000 events, half the limit): extra tests
/// wait for a free slot, keeping the suite green no matter how many Kafka
/// tests are added or how loaded the machine is.
static REDPANDA_SLOTS: Semaphore = Semaphore::const_new(3);

/// Pick a free local TCP port. There is a small race window between dropping
/// the temporary socket and the container binding the same port, but for a
/// single-node test it is acceptable.
pub fn free_local_port() -> u16 {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr: SocketAddr = listener.local_addr().expect("local address");
    drop(listener);
    addr.port()
}

fn redpanda_start_cmd(host_port: u16) -> Vec<String> {
    vec![
        "redpanda".to_string(),
        "start".to_string(),
        "--mode".to_string(),
        "dev-container".to_string(),
        // `--overprovisioned` tells seastar to size its reactor queues for
        // constrained/containerized environments, which reduces the AIO event
        // request per container from ~10000 to ~5000. The host kernel limit
        // (`/proc/sys/fs/aio-max-nr`, typically 65_536) is shared across
        // processes, so under `cargo test` (which runs multiple test
        // binaries in parallel, each starting its own Redpanda containers)
        // this keeps the cumulative AIO budget within range.
        "--overprovisioned".to_string(),
        "--smp=1".to_string(),
        "--memory=1G".to_string(),
        "--node-id=0".to_string(),
        "--kafka-addr=0.0.0.0:9092".to_string(),
        format!("--advertise-kafka-addr=127.0.0.1:{host_port}"),
    ]
}

/// Shared Redpanda start-up condition: the Kafka API server log line.
fn redpanda_ready_conditions() -> Vec<WaitFor> {
    vec![WaitFor::message_on_stderr("Started Kafka API server")]
}

/// A running Redpanda container together with the reachable bootstrap address.
pub struct RedpandaEnv {
    #[allow(dead_code)]
    container: ContainerAsync<Redpanda>,
    pub bootstrap_servers: String,
    /// Held for the container's lifetime; releases a `REDPANDA_SLOTS` slot
    /// on drop so a waiting test can start its own container.
    _slot: SemaphorePermit<'static>,
}

impl RedpandaEnv {
    pub async fn start() -> Self {
        let slot = REDPANDA_SLOTS
            .acquire()
            .await
            .expect("redpanda semaphore is never closed");
        let host_port = free_local_port();
        let image = Redpanda::new(host_port)
            .with_mapped_port(host_port, ContainerPort::Tcp(KAFKA_PORT));
        let container = image.start().await.expect("start redpanda container");
        Self {
            container,
            bootstrap_servers: format!("127.0.0.1:{host_port}"),
            _slot: slot,
        }
    }

    /// Consume `expected_count` messages from `topic` and return (key, payload)
    /// pairs decoded as UTF-8 strings.
    pub async fn consume_string(
        &self,
        topic: &str,
        expected_count: usize,
        timeout: Duration,
    ) -> Vec<(String, String)> {
        consume_string_with_config(
            &self.bootstrap_servers,
            topic,
            expected_count,
            timeout,
            ConsumerAuth::None,
        )
        .await
    }

    /// Consume `expected_count` messages from `topic` and return
    /// `(key, payload, headers)` triples. Headers are decoded as UTF-8 strings.
    pub async fn consume_with_headers(
        &self,
        topic: &str,
        expected_count: usize,
        timeout: Duration,
    ) -> Vec<(String, String, Vec<(String, String)>)> {
        consume_with_headers_config(
            &self.bootstrap_servers,
            topic,
            expected_count,
            timeout,
            ConsumerAuth::None,
        )
        .await
    }
}

/// Redpanda single-node image used for Kafka sink integration tests without
/// authentication.
#[derive(Debug, Clone)]
pub struct Redpanda {
    host_port: u16,
}

impl Redpanda {
    pub fn new(host_port: u16) -> Self {
        Self { host_port }
    }
}

impl Image for Redpanda {
    fn name(&self) -> &str {
        IMAGE_NAME
    }

    fn tag(&self) -> &str {
        IMAGE_TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        redpanda_ready_conditions()
    }

    fn cmd(
        &self,
    ) -> impl IntoIterator<Item = impl Into<std::borrow::Cow<'_, str>>> {
        redpanda_start_cmd(self.host_port)
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &[
            ContainerPort::Tcp(KAFKA_PORT),
            ContainerPort::Tcp(ADMIN_API_PORT),
        ]
    }
}

/// A running Redpanda container configured with SASL/SCRAM authentication.
pub struct RedpandaSaslEnv {
    #[allow(dead_code)]
    container: ContainerAsync<RedpandaSasl>,
    pub bootstrap_servers: String,
    pub username: String,
    pub password: String,
    /// Held for the container's lifetime; releases a `REDPANDA_SLOTS` slot
    /// on drop so a waiting test can start its own container.
    _slot: SemaphorePermit<'static>,
}

impl RedpandaSaslEnv {
    pub async fn start(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        let slot = REDPANDA_SLOTS
            .acquire()
            .await
            .expect("redpanda semaphore is never closed");
        let username = username.into();
        let password = password.into();
        let host_port = free_local_port();
        let image =
            RedpandaSasl::new(host_port, username.clone(), password.clone())
                .with_mapped_port(host_port, ContainerPort::Tcp(KAFKA_PORT));
        let container =
            image.start().await.expect("start redpanda sasl container");
        Self {
            container,
            bootstrap_servers: format!("127.0.0.1:{host_port}"),
            username,
            password,
            _slot: slot,
        }
    }

    /// Consume `expected_count` messages from `topic` authenticated with SASL.
    pub async fn consume_string(
        &self,
        topic: &str,
        expected_count: usize,
        timeout: Duration,
    ) -> Vec<(String, String)> {
        consume_string_with_config(
            &self.bootstrap_servers,
            topic,
            expected_count,
            timeout,
            ConsumerAuth::Sasl {
                username: &self.username,
                password: &self.password,
            },
        )
        .await
    }
}

/// Redpanda single-node image bootstrapped with SASL/SCRAM and a single
/// superuser. The user is created after the broker starts via `rpk`.
#[derive(Debug, Clone)]
pub struct RedpandaSasl {
    host_port: u16,
    username: String,
    password: String,
    bootstrap_copy: CopyToContainer,
}

impl RedpandaSasl {
    pub fn new(
        host_port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        let username = username.into();
        let password = password.into();
        let bootstrap_yaml = Self::bootstrap_yaml(&username);
        let bootstrap_copy = CopyToContainer::new(
            CopyDataSource::Data(bootstrap_yaml),
            "/etc/redpanda/.bootstrap.yaml",
        );
        Self {
            host_port,
            username,
            password,
            bootstrap_copy,
        }
    }

    fn bootstrap_yaml(username: &str) -> Vec<u8> {
        format!(
            "enable_sasl: true\nsuperusers:\n  - {username}\nauto_create_topics_enabled: true\n"
        )
        .into_bytes()
    }
}

impl Image for RedpandaSasl {
    fn name(&self) -> &str {
        IMAGE_NAME
    }

    fn tag(&self) -> &str {
        IMAGE_TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        redpanda_ready_conditions()
    }

    fn cmd(
        &self,
    ) -> impl IntoIterator<Item = impl Into<std::borrow::Cow<'_, str>>> {
        redpanda_start_cmd(self.host_port)
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &[
            ContainerPort::Tcp(KAFKA_PORT),
            ContainerPort::Tcp(ADMIN_API_PORT),
        ]
    }

    fn copy_to_sources(&self) -> impl IntoIterator<Item = &CopyToContainer> {
        std::iter::once(&self.bootstrap_copy)
    }

    fn exec_after_start(
        &self,
        _cs: testcontainers::core::ContainerState,
    ) -> testcontainers::core::error::Result<Vec<ExecCommand>> {
        Ok(vec![
            ExecCommand::new([
                "rpk",
                "acl",
                "user",
                "create",
                &self.username,
                "-p",
                &self.password,
                "--mechanism",
                "SCRAM-SHA-256",
            ])
            .with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
        ])
    }
}

/// A running Redpanda container configured with SCRAM (an admin user used by
/// the test consumer) and OAUTHBEARER/OIDC (used by the sink producer).
pub struct RedpandaOidcEnv {
    container: ContainerAsync<RedpandaOidc>,
    pub bootstrap_servers: String,
    pub admin_username: String,
    pub admin_password: String,
    /// Held for the container's lifetime; releases a `REDPANDA_SLOTS` slot
    /// on drop so a waiting test can start its own container.
    _slot: SemaphorePermit<'static>,
}

impl RedpandaOidcEnv {
    /// Start Redpanda with OIDC validation pointing at `discovery_url` (the
    /// mock IdP's discovery document) and a SCRAM admin user for consumers.
    /// The OIDC principal is a superuser, so no ACL or topic setup is
    /// needed (this test exercises OAUTHBEARER authentication, not broker
    /// authorization).
    pub async fn start(
        discovery_url: &str,
        audience: &str,
        oidc_principal: &str,
    ) -> Self {
        let slot = REDPANDA_SLOTS
            .acquire()
            .await
            .expect("redpanda semaphore is never closed");
        let admin_username = "admin".to_owned();
        let admin_password = "admin-secret".to_owned();
        let host_port = free_local_port();
        let image = RedpandaOidc::new(
            host_port,
            discovery_url,
            audience,
            admin_username.clone(),
            admin_password.clone(),
            oidc_principal,
        )
        .with_mapped_port(host_port, ContainerPort::Tcp(KAFKA_PORT))
        // Lets the container reach the host-side mock IdP both on Docker
        // Desktop (where `host.docker.internal` is native) and on native
        // Linux (via the host-gateway mapping).
        .with_host("host.docker.internal", Host::HostGateway);
        let container =
            image.start().await.expect("start redpanda oidc container");
        Self {
            container,
            bootstrap_servers: format!("127.0.0.1:{host_port}"),
            admin_username,
            admin_password,
            _slot: slot,
        }
    }

    /// Consume `expected_count` messages from `topic` authenticated with the
    /// SCRAM admin user.
    pub async fn consume_string(
        &self,
        topic: &str,
        expected_count: usize,
        timeout: Duration,
    ) -> Vec<(String, String)> {
        consume_string_with_config(
            &self.bootstrap_servers,
            topic,
            expected_count,
            timeout,
            ConsumerAuth::Sasl {
                username: &self.admin_username,
                password: &self.admin_password,
            },
        )
        .await
    }

    /// Container stdout + stderr, for failure diagnostics (OIDC validation
    /// errors are logged by redpanda, not returned to the client).
    pub async fn logs(&self) -> String {
        let stdout = self.container.stdout_to_vec().await.unwrap_or_default();
        let stderr = self.container.stderr_to_vec().await.unwrap_or_default();
        format!(
            "{}{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        )
    }
}

/// Redpanda single-node image bootstrapped with SCRAM (admin) and
/// OAUTHBEARER/OIDC validation against an external discovery URL. Both the
/// admin user and the OIDC principal are superusers.
#[derive(Debug, Clone)]
pub struct RedpandaOidc {
    host_port: u16,
    admin_username: String,
    admin_password: String,
    bootstrap_copy: CopyToContainer,
}

impl RedpandaOidc {
    pub fn new(
        host_port: u16,
        discovery_url: &str,
        audience: &str,
        admin_username: impl Into<String>,
        admin_password: impl Into<String>,
        oidc_principal: &str,
    ) -> Self {
        let admin_username = admin_username.into();
        let admin_password = admin_password.into();
        let bootstrap_yaml = format!(
            "enable_sasl: true\n\
             superusers:\n  - {admin_username}\n  - {oidc_principal}\n\
             sasl_mechanisms: ['SCRAM', 'OAUTHBEARER']\n\
             oidc_discovery_url: {discovery_url}\n\
             oidc_principal_mapping: $.sub\n\
             oidc_token_audience: {audience}\n\
             auto_create_topics_enabled: true\n"
        );
        let bootstrap_copy = CopyToContainer::new(
            CopyDataSource::Data(bootstrap_yaml.into_bytes()),
            "/etc/redpanda/.bootstrap.yaml",
        );
        Self {
            host_port,
            admin_username,
            admin_password,
            bootstrap_copy,
        }
    }
}

impl Image for RedpandaOidc {
    fn name(&self) -> &str {
        IMAGE_NAME
    }

    fn tag(&self) -> &str {
        IMAGE_TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        redpanda_ready_conditions()
    }

    fn cmd(
        &self,
    ) -> impl IntoIterator<Item = impl Into<std::borrow::Cow<'_, str>>> {
        redpanda_start_cmd(self.host_port)
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &[
            ContainerPort::Tcp(KAFKA_PORT),
            ContainerPort::Tcp(ADMIN_API_PORT),
        ]
    }

    fn copy_to_sources(&self) -> impl IntoIterator<Item = &CopyToContainer> {
        std::iter::once(&self.bootstrap_copy)
    }

    fn exec_after_start(
        &self,
        _cs: testcontainers::core::ContainerState,
    ) -> testcontainers::core::error::Result<Vec<ExecCommand>> {
        Ok(vec![
            ExecCommand::new([
                "rpk",
                "acl",
                "user",
                "create",
                &self.admin_username,
                "-p",
                &self.admin_password,
                "--mechanism",
                "SCRAM-SHA-256",
            ])
            .with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
        ])
    }
}

/// Redpanda single-node image bootstrapped with TLS (server certificate).
/// The client must trust the CA and can optionally present a client cert.
#[derive(Debug, Clone)]
pub struct RedpandaTls {
    host_port: u16,
    config_copy: CopyToContainer,
    ca_copy: CopyToContainer,
    cert_copy: CopyToContainer,
    key_copy: CopyToContainer,
}

impl RedpandaTls {
    pub fn new(host_port: u16, material: &TestTlsMaterial) -> Self {
        let config_yaml = Self::tls_bootstrap_yaml(host_port);
        let config_copy = CopyToContainer::new(
            CopyDataSource::Data(config_yaml),
            "/tmp/redpanda.yaml",
        );
        let ca_copy = CopyToContainer::new(
            CopyDataSource::Data(material.ca_pem.clone().into()),
            "/tmp/ca.crt",
        );
        let cert_copy = CopyToContainer::new(
            CopyDataSource::Data(material.server_cert_pem.clone().into()),
            "/tmp/server.crt",
        );
        let key_copy = CopyToContainer::new(
            CopyDataSource::Data(material.server_key_pem.clone().into()),
            "/tmp/server.key",
        );
        Self {
            host_port,
            config_copy,
            ca_copy,
            cert_copy,
            key_copy,
        }
    }

    fn tls_bootstrap_yaml(host_port: u16) -> Vec<u8> {
        format!(
            r#"redpanda:
    data_directory: /var/lib/redpanda/data
    node_id: 0
    kafka_api:
        - address: 0.0.0.0
          port: 9092
          name: tls_listener
    kafka_api_tls:
        - name: tls_listener
          key_file: /tmp/server.key
          cert_file: /tmp/server.crt
          truststore_file: /tmp/ca.crt
          enabled: true
    advertised_kafka_api:
        - address: 127.0.0.1
          port: {host_port}
          name: tls_listener
    developer_mode: true
    auto_create_topics_enabled: true
"#
        )
        .into_bytes()
    }
}

impl Image for RedpandaTls {
    fn name(&self) -> &str {
        IMAGE_NAME
    }

    fn tag(&self) -> &str {
        IMAGE_TAG
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        redpanda_ready_conditions()
    }

    fn entrypoint(&self) -> Option<&str> {
        Some("redpanda")
    }

    fn cmd(
        &self,
    ) -> impl IntoIterator<Item = impl Into<std::borrow::Cow<'_, str>>> {
        vec![
            "--redpanda-cfg".to_string(),
            "/tmp/redpanda.yaml".to_string(),
            "-c".to_string(),
            "1".to_string(),
            "-m".to_string(),
            "1G".to_string(),
        ]
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &[
            ContainerPort::Tcp(KAFKA_PORT),
            ContainerPort::Tcp(ADMIN_API_PORT),
        ]
    }

    fn copy_to_sources(&self) -> impl IntoIterator<Item = &CopyToContainer> {
        [
            &self.config_copy,
            &self.ca_copy,
            &self.cert_copy,
            &self.key_copy,
        ]
    }
}

/// A running Redpanda container configured with TLS. The client must trust
/// the generated CA.
pub struct RedpandaTlsEnv {
    #[allow(dead_code)]
    container: ContainerAsync<RedpandaTls>,
    pub bootstrap_servers: String,
    /// CA certificate in PEM; the client must trust it.
    pub ca_pem: String,
    /// Client certificate in PEM; for mTLS tests.
    pub client_cert_pem: String,
    /// Client private key in PEM; for mTLS tests.
    pub client_key_pem: String,
    _slot: SemaphorePermit<'static>,
}

impl RedpandaTlsEnv {
    pub async fn start() -> Self {
        let slot = REDPANDA_SLOTS
            .acquire()
            .await
            .expect("redpanda semaphore is never closed");
        let host_port = free_local_port();
        let material = TestTlsMaterial::generate();
        let image = RedpandaTls::new(host_port, &material)
            .with_mapped_port(host_port, ContainerPort::Tcp(KAFKA_PORT));
        let container =
            image.start().await.expect("start redpanda tls container");
        Self {
            container,
            bootstrap_servers: format!("127.0.0.1:{host_port}"),
            ca_pem: material.ca_pem,
            client_cert_pem: material.client_cert_pem,
            client_key_pem: material.client_key_pem,
            _slot: slot,
        }
    }

    /// Consume `expected_count` messages from `topic` over TLS.
    pub async fn consume_string(
        &self,
        topic: &str,
        expected_count: usize,
        timeout: Duration,
    ) -> Vec<(String, String)> {
        consume_string_tls(
            &self.bootstrap_servers,
            topic,
            expected_count,
            timeout,
            &self.ca_pem,
        )
        .await
    }
}

enum ConsumerAuth<'a> {
    None,
    Sasl {
        username: &'a str,
        password: &'a str,
    },
}

fn consumer_config(
    bootstrap_servers: &str,
    group_id: &str,
    auth: ConsumerAuth<'_>,
) -> ClientConfig {
    let mut cfg = ClientConfig::new();
    cfg.set("group.id", group_id)
        .set("bootstrap.servers", bootstrap_servers)
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest");

    if let ConsumerAuth::Sasl { username, password } = auth {
        cfg.set("security.protocol", "SASL_PLAINTEXT")
            .set("sasl.mechanism", "SCRAM-SHA-256")
            .set("sasl.username", username)
            .set("sasl.password", password);
    }

    cfg
}

/// Consume the next message from `stream`, polling with short per-attempt
/// timeouts instead of a single long timeout. Returns as soon as a message
/// arrives; fails only after many attempts, so slow systems have ample time.
/// Returns owned strings to avoid lifetime issues with the borrowed message.
///
/// `UnknownTopicOrPartition` / `UnknownTopic` are treated as "topic not yet
/// auto-created": the consumer keeps polling until the sink's first produce
/// creates the topic or the overall timeout elapses. Any other consumer
/// error is fatal.
async fn consume_next<C: rdkafka::consumer::ConsumerContext>(
    stream: &mut rdkafka::consumer::MessageStream<'_, C>,
    timeout: Duration,
) -> (String, String, Vec<(String, String)>) {
    use rdkafka::message::Headers as _;

    let per_attempt = Duration::from_millis(100);
    let max_attempts = timeout.as_millis() / per_attempt.as_millis();
    let mut attempts = 0;
    loop {
        match tokio::time::timeout(per_attempt, stream.next()).await {
            Ok(Some(Ok(msg))) => {
                let key = msg
                    .key()
                    .map(|k| String::from_utf8_lossy(k).to_string())
                    .unwrap_or_default();
                let payload = msg
                    .payload()
                    .map(|p| String::from_utf8_lossy(p).to_string())
                    .unwrap_or_default();
                let headers = msg
                    .headers()
                    .map(|h| {
                        (0..h.count())
                            .map(|i| {
                                let header = h.get(i);
                                (
                                    header.key.to_owned(),
                                    header
                                        .value
                                        .map(|v| {
                                            String::from_utf8_lossy(v)
                                                .into_owned()
                                        })
                                        .unwrap_or_default(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                return (key, payload, headers);
            }
            Ok(Some(Err(e))) => {
                if is_topic_not_found(&e) {
                    if attempts >= max_attempts {
                        panic!(
                            "consume timed out after {:?} ({} attempts) waiting for topic to be created",
                            timeout, attempts
                        );
                    }
                    attempts += 1;
                    continue;
                }
                panic!("consumer message error: {e}");
            }
            Ok(None) => panic!("consumer stream ended"),
            Err(_) => {
                if attempts >= max_attempts {
                    panic!(
                        "consume timed out after {:?} ({} attempts)",
                        timeout, attempts
                    );
                }
                attempts += 1;
            }
        }
    }
}

/// Whether the error means the consumer subscribed to a topic the broker does
/// not know about yet. Kafka/Redpanda create topics on the first produce, so
/// a test that consumes before the sink's first produce sees this and must
/// keep polling rather than failing.
fn is_topic_not_found(err: &KafkaError) -> bool {
    matches!(
        err,
        KafkaError::MessageConsumption(
            RDKafkaErrorCode::UnknownTopicOrPartition
                | RDKafkaErrorCode::UnknownTopic,
        )
    )
}

async fn consume_string_with_config(
    bootstrap_servers: &str,
    topic: &str,
    expected_count: usize,
    timeout: Duration,
    auth: ConsumerAuth<'_>,
) -> Vec<(String, String)> {
    // Use a unique consumer group per topic so parallel tests do not interfere
    // with each other through shared group state.
    let group_id = format!("test-group-{topic}");
    let consumer: StreamConsumer =
        consumer_config(bootstrap_servers, &group_id, auth)
            .create()
            .expect("create stream consumer");
    consumer.subscribe(&[topic]).expect("subscribe to topic");

    let mut stream = consumer.stream();
    let mut out = Vec::with_capacity(expected_count);
    for _ in 0..expected_count {
        let (key, payload, _headers) = consume_next(&mut stream, timeout).await;
        out.push((key, payload));
    }
    out
}

async fn consume_with_headers_config(
    bootstrap_servers: &str,
    topic: &str,
    expected_count: usize,
    timeout: Duration,
    auth: ConsumerAuth<'_>,
) -> Vec<(String, String, Vec<(String, String)>)> {
    let group_id = format!("test-group-headers-{topic}");
    let consumer: StreamConsumer =
        consumer_config(bootstrap_servers, &group_id, auth)
            .create()
            .expect("create stream consumer");
    consumer.subscribe(&[topic]).expect("subscribe to topic");

    let mut stream = consumer.stream();
    let mut out = Vec::with_capacity(expected_count);
    for _ in 0..expected_count {
        let (key, payload, headers) = consume_next(&mut stream, timeout).await;
        out.push((key, payload, headers));
    }
    out
}

fn consumer_config_tls(
    bootstrap_servers: &str,
    group_id: &str,
    ca_pem: &str,
) -> ClientConfig {
    let mut cfg = ClientConfig::new();
    cfg.set("group.id", group_id)
        .set("bootstrap.servers", bootstrap_servers)
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "false")
        .set("auto.offset.reset", "earliest")
        .set("security.protocol", "ssl")
        .set("ssl.ca.pem", ca_pem);
    cfg
}

async fn consume_string_tls(
    bootstrap_servers: &str,
    topic: &str,
    expected_count: usize,
    timeout: Duration,
    ca_pem: &str,
) -> Vec<(String, String)> {
    let group_id = format!("test-group-tls-{topic}");
    let consumer: StreamConsumer =
        consumer_config_tls(bootstrap_servers, &group_id, ca_pem)
            .create()
            .expect("create tls stream consumer");
    consumer.subscribe(&[topic]).expect("subscribe to topic");

    let mut stream = consumer.stream();
    let mut out = Vec::with_capacity(expected_count);
    for _ in 0..expected_count {
        let (key, payload, _headers) = consume_next(&mut stream, timeout).await;
        out.push((key, payload));
    }
    out
}
