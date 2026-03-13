# ave-http

HTTP API server for the Ave stack.

`ave-http` is the web-facing crate in the Ave workspace. It builds on top of `ave-bridge` and exposes the runtime through an Axum-based HTTP API, including authentication, administration, OpenAPI documentation, TLS support, audit logging, and optional Prometheus metrics.

If `ave-bridge` is the integration layer for applications, `ave-http` is the ready-to-run HTTP surface for operating and administering an Ave node.

## What this crate provides

- Axum-based HTTP routes for the Ave runtime
- OpenAPI schema generation and Swagger UI
- authentication and authorization middleware
- user, role, permission, API key, quota, and audit-log management endpoints
- HTTP and HTTPS serving, including self-signed certificate support
- request tracing and file/stdout logging integration
- optional Prometheus metrics exposure

## When to use `ave-http`

Use `ave-http` when you need:

- a complete HTTP server around the Ave runtime
- an admin API for users, roles, API keys, quotas, and system configuration
- browser-facing docs through OpenAPI and Swagger UI
- TLS termination and operational HTTP concerns handled inside the crate

If you only need to embed the runtime in another service, use `ave-bridge` or `ave-core` instead.

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `sqlite` | Yes | Uses SQLite-backed internal persistence via `ave-bridge` |
| `rocksdb` | No | Uses RocksDB-backed internal persistence via `ave-bridge` |
| `ext-sqlite` | Yes | Enables the external SQLite integration required by the runtime |
| `prometheus` | Yes | Exposes Prometheus metrics support |

## Installation

Default setup:

```toml
[dependencies]
ave-http = "0.8.0"
```

RocksDB-based internal storage:

```toml
[dependencies]
ave-http = { version = "0.8.0", default-features = false, features = ["rocksdb", "ext-sqlite", "prometheus"] }
```

## What is inside

The crate is organized around a few main areas:

- `startup`: process startup, server boot, TLS wiring, and runtime assembly
- `server`: route construction and HTTP handlers for the Ave runtime API
- `auth`: authentication database, admin handlers, middleware, rate limits, quotas, API keys, and audit logs
- `doc`: OpenAPI generation and Swagger UI integration
- `logging`: tracing and file logging setup
- `middleware`: shared HTTP middleware such as tracing
- `config_types`: HTTP-facing configuration DTOs

## Runtime surface

The HTTP server exposes endpoints for:

- peer identity and node configuration
- network state and request tracking
- approvals, subjects, events, and aborts
- manual distribution and update flows
- auth subject and witness management
- administrative auth operations such as users, roles, permissions, API keys, quotas, audit logs, and system configuration

## Authentication and admin system

`ave-http` includes its own HTTP auth subsystem on top of the runtime. That subsystem covers:

- credential-based login
- API key issuance and rotation
- role and permission management
- endpoint-level authorization
- audit logging
- rate limiting and lockout controls
- usage plans and quota extensions

This makes the crate suitable not just as a transport wrapper, but as the operational control plane for an Ave deployment.

## OpenAPI and docs

The crate generates an OpenAPI description with `utoipa` and can expose Swagger UI routes. That is useful both for interactive exploration and for integrating the API into external tooling.

## TLS and deployment options

`ave-http` supports:

- plain HTTP serving
- HTTPS serving with configured certificate and private key paths
- optional self-signed certificate generation and renewal support
- proxy-aware request metadata and forwarded-IP handling
- CORS configuration for browser-based clients

## Configuration shape

Although process startup is driven by the binary in this crate, the HTTP layer depends on the broader bridge configuration model from `ave-bridge`. In practice that means the deployed service is configured across:

- node runtime settings
- auth settings
- HTTP and TLS settings
- logging settings
- sink settings

## Ecosystem fit

Within the Ave stack:

- `ave-common` provides shared domain types
- `ave-network` provides peer-to-peer networking
- `ave-core` provides the runtime engine
- `ave-bridge` provides the application integration layer
- `ave-http` provides the full HTTP control and data API

If you want to run or expose Ave over HTTP, this is the crate to depend on.
