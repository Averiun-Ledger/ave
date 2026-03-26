# Ave

Open-source Rust workspace for building, embedding, and exposing Ave ledger nodes.

Ave is organized as a set of crates that cover the full stack of a node:

- cryptographic identity primitives
- shared domain and API types
- peer-to-peer networking
- runtime orchestration and contract execution
- application integration
- a ready-to-run HTTP API server

This repository is intended both for users who want to run Ave components and for developers who want to inspect, extend, or reuse parts of the stack.

The repository root also publishes the aggregate `ave` crate. That crate re-exports the main workspace crates so consumers can depend on a single package and reach:

- `ave::identity`
- `ave::common`
- `ave::network`
- `ave::core`
- `ave::bridge`
- `ave::http` when the `http` feature is enabled

## What this repository contains

The workspace is split into focused crates:

| Crate | Purpose |
|---|---|
| [`ave-identity`](./identity) | Cryptographic primitives, keys, signatures, hashes |
| [`ave-common`](./common) | Shared domain models, bridge types, and common utilities |
| [`ave-network`](./network) | libp2p-based peer-to-peer networking layer |
| [`ave-core`](./core) | Main runtime engine for building and running Ave nodes |
| [`ave-bridge`](./bridge) | Application-facing integration layer over the runtime |
| [`ave-http`](./http) | Axum-based HTTP API, auth system, admin surface, and startup wiring |

The runtime also depends on the sibling [`ave-actors`](../ave-actors) workspace for the actor model and persistence backends.

## How the pieces fit together

At a high level:

1. `ave-identity` provides keys, signatures, and digest types.
2. `ave-common` defines the shared request, response, governance, and bridge-facing models.
3. `ave-network` provides peer discovery, messaging, and node networking.
4. `ave-core` combines networking, persistence, contract execution, and workflow logic into a node runtime.
5. `ave-bridge` wraps the runtime into a simpler integration surface for services and applications.
6. `ave-http` exposes that integration layer over HTTP with authentication, admin APIs, OpenAPI, and operational middleware.

If you only need one layer, you can depend on that crate directly. If you want the full HTTP server, start with `ave-http`.

## Main capabilities

- event-driven node runtime built in Rust
- actor-based orchestration
- peer-to-peer networking over libp2p
- internal persistence with SQLite or RocksDB
- external SQLite-backed ledger/state storage
- Wasmtime-based contract execution
- sink delivery to external systems with retries and auth bootstrap
- HTTP API with auth, admin endpoints, quotas, API keys, and audit logs
- OpenAPI generation and Swagger UI
- Prometheus metrics support

## Repository layout

Top-level folders you will likely care about first:

- [`identity`](./identity): crypto crate
- [`common`](./common): shared models
- [`network`](./network): P2P layer
- [`core`](./core): runtime engine
- [`bridge`](./bridge): application integration layer
- [`http`](./http): HTTP server and Docker build flow

If you are browsing the code for the first time, a good reading order is:

1. [`core/README.md`](./core/README.md)
2. [`network/README.md`](./network/README.md)
3. [`bridge/README.md`](./bridge/README.md)
4. [`http/README.md`](./http/README.md)

## Getting started

### Requirements

- Rust toolchain compatible with the workspace `rust-version`
- Cargo
- Docker, if you want to build the container images from `http/docker`

### Build the workspace

```bash
cargo build --workspace
```

### Run the workspace tests

```bash
cargo test --workspace
```

### Check formatting and lints

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
```

## Running the HTTP server

The ready-to-run executable is in the `ave-http` crate.

Run it with the default feature set:

```bash
cargo run -p ave-http
```

Feature constraints used across the runtime:

- exactly one of `sqlite` or `rocksdb` must be enabled
- `ext-sqlite` is required by the current runtime

Example with RocksDB internal storage:

```bash
cargo run -p ave-http --no-default-features --features "rocksdb ext-sqlite prometheus"
```

## Docker builds

The repository includes Docker build assets under [`http/docker`](./http/docker).

The main build helper is:

- [`http/docker/build.sh`](./http/docker/build.sh)

That script supports:

- production builds for both AMD64 and ARM64
- development builds for selected architectures
- SQLite and RocksDB variants
- separate Cargo profiles for production and experimental builds

## Configuration

Configuration is layered through the workspace:

- `ave-core` defines the runtime configuration
- `ave-bridge` adds application, auth, logging, sink, and HTTP-related settings
- `ave-http` uses that configuration to start the full HTTP service

The most important configuration areas are:

- key management
- network addresses and boot nodes
- internal and external database paths
- logging outputs and rotation
- sink destinations and sink auth
- HTTP, TLS, proxy, and CORS behavior
- auth and rate-limit settings

## Which crate should I use?

- Use the root `ave` crate if you want one dependency that re-exports the main workspace crates.
- Use [`ave-http`](./http) if you want a complete HTTP server.
- Use [`ave-bridge`](./bridge) if you want to embed Ave into an application or daemon.
- Use [`ave-core`](./core) if you want the runtime engine directly.
- Use [`ave-network`](./network) if you only need the P2P layer.
- Use [`ave-common`](./common) for shared domain and API models.
- Use [`ave-identity`](./identity) for cryptographic primitives.

## For developers reading the code

If you are here to understand the internals rather than just use the crates:

- start in [`core/src/lib.rs`](./core/src/lib.rs) to see the runtime entry points
- inspect [`network/src/lib.rs`](./network/src/lib.rs) and [`network/src/worker.rs`](./network/src/worker.rs) for the networking layer
- inspect [`bridge/src/lib.rs`](./bridge/src/lib.rs) for the integration facade
- inspect [`http/src/startup.rs`](./http/src/startup.rs) and [`http/src/server.rs`](./http/src/server.rs) for process startup and HTTP routes

That path gives a reasonable top-down view of how the workspace is assembled.

## Root crate usage

If you prefer to depend on the aggregate crate instead of individual workspace crates:

```toml
[dependencies]
ave = "0.9.0"
```

Enable the HTTP layer re-export only when you need it:

```toml
[dependencies]
ave = { version = "0.9.0", features = ["http"] }
```

## Open source

Ave is free software. The source is published so it can be studied, audited, adapted, and improved by others.

This project is a fork of [kore](https://github.com/kore-ledger/kore), originally developed by Kore Ledger, SL, modified in 2025 by Averiun Ledger, SL, and distributed under the same AGPL-3.0-only license.
