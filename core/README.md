# ave-core

High-level runtime for building and running Ave ledger nodes.

`ave-core` is the crate that assembles the full node runtime on top of `ave-common`, `ave-network`, and `ave-actors`. It wires together request processing, governance flows, contract execution, persistence, outbound sink delivery, and network orchestration behind a single bootstrap API.

If you are embedding an Ave node in a service or binary, this is the crate you depend on.

## What this crate includes

- `Api`, the main entry point used to bootstrap and operate a node runtime
- Node and service orchestration built on the actor system
- Governance, approval, request, tracker, subject, and update workflows
- Wasmtime-based contract compilation and execution
- Internal persistence backed by SQLite or RocksDB
- External SQLite-backed ledger/state storage
- Sink delivery with routing, retries, token bootstrap, and request timeouts
- Prometheus metrics registration hooks

## When to use `ave-core`

Use `ave-core` when you need the full runtime:

- a node process
- a service process that embeds node behavior
- an integration binary that must validate, execute, persist, and distribute ledger requests

If you only need shared types or cryptographic primitives, prefer lower-level crates:

- `ave-common` for shared domain models and protocol types
- `ave-identity` for key, signature, and hash primitives
- `ave-network` for the P2P transport layer on its own

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `sqlite` | Yes | Enables SQLite-backed internal persistence through `ave-actors` |
| `rocksdb` | No | Enables RocksDB-backed internal persistence through `ave-actors` |
| `ext-sqlite` | Yes | Enables the external SQLite database integration used by the runtime |
| `test` | No | Internal development feature used by this crate's own test suite |

Constraints enforced by the crate:

- Exactly one of `sqlite` or `rocksdb` must be enabled.
- `ext-sqlite` is currently required.

## Installation

Default SQLite-based runtime:

```toml
[dependencies]
ave-core = "0.12.0"
```

RocksDB-based internal storage:

```toml
[dependencies]
ave-core = { version = "0.12.0", default-features = false, features = ["rocksdb", "ext-sqlite"] }
```

## Bootstrap example

```rust,ignore
use ave_common::identity::{KeyPair, KeyPairAlgorithm};
use ave_core::{
    config::{Config, SinkConfigEntry},
    Api,
};
use prometheus_client::registry::Registry;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = KeyPair::generate(KeyPairAlgorithm::Ed25519)?;
    let config = Config::default();
    let mut registry = Registry::default();
    let graceful = CancellationToken::new();
    let crash = CancellationToken::new();

    let (_api, runners) = Api::build(
        keys,
        config,
        Vec::<SinkConfigEntry>::new(),
        &mut registry,
        "change-me",
        graceful.clone(),
        crash,
    )
    .await?;

    for runner in runners {
        tokio::spawn(async move {
            let _ = runner.await;
        });
    }

    Ok(())
}
```

`Api::build` returns:

- the initialized `Api` facade
- the background task handles that keep the runtime alive

The host application is responsible for driving those tasks for the lifetime of the node.

## Configuration overview

The main configuration type is `ave_core::config::Config`.

It covers:

- keypair and hash algorithm selection
- internal database backend and storage path
- external database path
- P2P network configuration
- contract directory
- sink auth and sink delivery behavior
- tracking cache sizing
- safe mode for isolated maintenance tasks
- machine sizing hints for Wasmtime execution

If no machine sizing is provided, the runtime auto-detects available RAM and CPU cores from the host.

## Storage model

`ave-core` separates persistence into two areas:

- internal storage for actor-backed runtime state, using SQLite or RocksDB
- external SQLite storage for ledger-facing state and queries

This split lets the runtime keep actor/system state independent from the externally queried data model.

## Contracts and execution

Contracts are compiled and executed through Wasmtime. The runtime exposes machine sizing hints so execution limits can be tuned to the target host class without hardcoding a single configuration.

## Sink delivery

The runtime includes outbound sink handling for propagating events to external systems. Sink delivery supports:

- multiple sink destinations per schema
- ordered or round-robin routing
- bounded queues
- timeout and retry policies
- token bootstrap and token refresh flows

## Kafka sink operations

Operational notes for running a Kafka sink in production.

### Broker ACLs

The identity used by the sink needs at least:

- `Write` and `Describe` on every target topic.
- With idempotence enabled (the default when `acks=all`) or transactions
  (`transactional: true`): `IdempotentWrite` / `InitProducerId` on the
  cluster, plus `Write` and `Describe` on the transactional id resource when
  transactions are used.

A missing ACL surfaces as an auth error on delivery and sends the sink to
the lagging/blocked state; it does not crash the node.

### Environment variables

Secrets are never written in the configuration file. They are read from
environment variables named after the sink, upper-cased with every
non-alphanumeric character replaced by `_`:

- `AVE_SINK_PASSWORD_{{SERVER}}` — SASL password (PLAIN/SCRAM) or OIDC
  client secret (OAUTHBEARER).
- `AVE_SINK_APIKEY_{{SERVER}}` — API key, when configured.
- `AVE_SINK_PROXY_PASSWORD_{{SERVER}}` — proxy password (HTTP sinks).

Example: a sink named `billing-events.eu` reads
`AVE_SINK_PASSWORD_BILLING_EVENTS_EU`.

### SASL authentication

- `PLAIN` / `SCRAM-SHA-256` / `SCRAM-SHA-512`: username in the sink config,
  password in `AVE_SINK_PASSWORD_{{SERVER}}`.
- `OAUTHBEARER` (OIDC): set `oauth_token_url` to the IdP token endpoint; the
  SASL username is the OIDC client id and the client secret is read from
  `AVE_SINK_PASSWORD_{{SERVER}}`. Tokens are fetched with the
  `client_credentials` grant and refreshed automatically before expiry;
  `oauth_scope` is optional.
- `GSSAPI` (Kerberos): fill the `kerberos` section (`service_name`,
  `principal`, `keytab`); the realm is derived from the principal. The host
  needs a working Kerberos setup (krb5.conf, keytab readable by the node
  process) and a librdkafka build with Cyrus SASL (`sasl_gssapi` in
  `builtin.features`).

### Topics

Pre-create the target topics with the desired partition count and
replication factor. If broker-side auto-creation is disabled, deliveries
fail with `UnknownTopicOrPartition` and are retried indefinitely: the sink
does not die, but it does not deliver until the topic exists.

### Transactions

With `transactional: true` every delivery is its own Kafka transaction
(begin/send/commit, abort on failure) and the producer fences zombie
instances of itself at startup. The default `transactional.id` is
`ave-sink-{sink_name}-{node_id}`, stable and unique per node, so several
nodes can run the same sink without fencing each other. If you set
`transactional_id` explicitly in a multi-node deployment, it must differ
per node. Transactions require `acks=all`; the configuration is rejected
otherwise.

### Metrics to watch

- `core_kafka_producer_queue_size{sink}` — producer queue depth; sustained
  growth means the broker cannot keep up (backpressure).
- `core_kafka_producer_tx_errors_total{sink}` — transmission errors and
  request timeouts reported by librdkafka.
- `core_kafka_producer_fatal_errors_total{sink}` — fatal producer errors
  (fenced, unsupported feature). The producer instance is dead after one of
  these; alert on any increase.
- `core_kafka_producer_rtt_seconds{sink}` — broker round-trip time.
- `core_sink_request_duration_seconds{sink,result}` — per-attempt delivery
  latency.
- `core_sink_events_total{sink,result}` and `core_sink_blocked{sink}` —
  delivery outcomes and blocked state.

### Poison messages

A permanently rejected event (for example, a payload larger than the
broker's `max.message.bytes`) blocks the sink: subsequent events queue
behind it until the underlying cause is fixed and the sink is unblocked.
There is no dead-letter queue yet; watch `core_sink_blocked{sink}` and the
sink status API for the blocked reason.

## Crate layout

Public modules are grouped by responsibility:

- `config` and `error` for setup and top-level error handling
- `request`, `validation`, `approval`, and `governance` for request lifecycles
- `subject`, `tracker`, and `update` for domain state handling
- `evaluation` for contract execution
- `helpers` for runtime support code such as sinks, networking bridges, and database helpers
- `system` and `node` for actor-system bootstrap and node composition

## Operational note

This crate is designed to be embedded by binaries and services rather than used as a collection of isolated helpers. The intended entry point is `Api::build`, not piecemeal construction of internal actors.

## Safe mode and maintenance

`ave-core::config::Config` includes a `safe_mode` flag for isolated maintenance
work.

When enabled, the runtime keeps read/query operations available but blocks
normal mutating operations. It also exposes maintenance-only subject deletion
through the top-level API so trackers and governances can be removed in a
controlled way without joining the network.

Manual update calls can also run in strict mode. In strict mode the updater only
contacts the witnesses explicitly provided through auth configuration and does
not expand the candidate set through governance discovery.
