# ave-bridge

Application-facing bridge for embedding and configuring the Ave runtime.

`ave-bridge` sits on top of `ave-core` and exposes a simpler integration layer for services and binaries. It combines runtime bootstrap, configuration loading, key handling, HTTP-related settings, sink auth bootstrap, and a higher-level API surface for interacting with an Ave node.

If `ave-core` is the full runtime engine, `ave-bridge` is the crate intended to wire that runtime into an application.

## What this crate provides

- `Bridge`, the main facade used to build and operate an embedded Ave node
- `Config`, a top-level application configuration that wraps node, auth, sink, logging, and HTTP settings
- re-exports of the most relevant runtime configuration types from `ave-core` and `ave-network`
- conversions between bridge-facing request/response types and the lower-level runtime types
- configuration loading and validation helpers in `settings`
- optional Prometheus route support

## When to use `ave-bridge`

Use `ave-bridge` when you need:

- a stable integration layer for an application or daemon
- configuration loading from files plus runtime validation
- a single facade over node runtime, network config, and HTTP settings
- convenient access to higher-level request and query methods without wiring `ave-core` manually

If you are building the runtime itself, use `ave-core`.

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `sqlite` | Yes | Uses SQLite-backed internal persistence via `ave-core` |
| `rocksdb` | No | Uses RocksDB-backed internal persistence via `ave-core` |
| `ext-sqlite` | Yes | Enables the external SQLite integration required by the runtime |
| `prometheus` | Yes | Enables Prometheus HTTP route support |
| `openapi` | No | Enables OpenAPI-related shared types from `ave-common` |
| `test` | No | Internal development feature used by the workspace tests |

Constraints enforced by the crate:

- Exactly one of `sqlite` or `rocksdb` must be enabled.
- `ext-sqlite` is required.

## Installation

Default setup:

```toml
[dependencies]
ave-bridge = "0.8.0"
```

RocksDB-based internal storage:

```toml
[dependencies]
ave-bridge = { version = "0.8.0", default-features = false, features = ["rocksdb", "ext-sqlite", "prometheus"] }
```

## Bootstrap example

```rust,ignore
use ave_bridge::{Bridge, Config};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Config::default();
    let graceful = CancellationToken::new();
    let crash = CancellationToken::new();

    let (_bridge, runners) = Bridge::build(
        &settings,
        "node-password",
        "sink-password",
        "",
        Some(graceful),
        Some(crash),
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

`Bridge::build` creates the underlying `ave-core` runtime, initializes sink auth when needed, and returns the background task handles that the host process must keep alive.

## Configuration model

The main configuration type is `ave_bridge::config::Config`.

It groups:

- `node`: the underlying `ave-core` runtime configuration
- `keys_path`: the location of encrypted key material
- `logging`: output and rotation settings
- `sink`: sink routing and authentication settings
- `auth`: application authentication settings
- `http`: HTTP, proxy, CORS, and self-signed certificate settings

The `settings` module can load this configuration from JSON, YAML, or TOML and runs validation for:

- HTTPS settings
- network queue and memory-limit settings
- control-list settings
- address and boot-node consistency

## HTTP-related types

Even though the HTTP server itself lives elsewhere in the workspace, `ave-bridge` provides shared HTTP-facing configuration types such as:

- `HttpConfig`
- `ProxyConfig`
- `CorsConfig`
- `SelfSignedCertConfig`

That makes this crate the configuration boundary between the application layer and the runtime layer.

## API surface

The `Bridge` facade exposes higher-level methods for common operations, including:

- retrieving peer identity and runtime config
- checking network state
- posting event requests
- querying approvals, requests, subjects, events, and aborts
- managing auth subjects and witnesses
- manual distribution and update operations

This lets application code stay mostly unaware of the actor-system internals in `ave-core`.

## Re-exports

`ave-bridge` re-exports the most relevant types needed by integrators, including pieces from:

- `ave-core`
- `ave-network`
- `ave-common`
- `clap`

The goal is to reduce the number of direct dependencies an embedding application needs to understand.

## Ecosystem fit

Within the Ave stack:

- `ave-common` provides shared domain types
- `ave-network` provides the peer-to-peer layer
- `ave-core` provides the runtime engine
- `ave-bridge` provides the application integration layer

If your code is deciding how to configure, start, and call into an Ave node, this is the crate to depend on.
