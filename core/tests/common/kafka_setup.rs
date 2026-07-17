use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use futures::StreamExt;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::{ClientConfig, Message};
use testcontainers::core::{
    CmdWaitFor, ContainerPort, CopyDataSource, CopyToContainer, ExecCommand,
    WaitFor,
};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, Image, ImageExt};
use tokio::sync::{Semaphore, SemaphorePermit};

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
        "--smp=1".to_string(),
        "--memory=1G".to_string(),
        "--overprovisioned".to_string(),
        "--node-id=0".to_string(),
        "--check=false".to_string(),
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
        let msg = tokio::time::timeout(timeout, stream.next())
            .await
            .expect("consume timed out")
            .expect("consumer stream ended")
            .expect("consumer message error");
        let key = msg
            .key()
            .map(|k| String::from_utf8_lossy(k).to_string())
            .unwrap_or_default();
        let payload = msg
            .payload()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_default();
        out.push((key, payload));
    }
    out
}
