# ave-common

`ave-common` contains the shared domain types used across the Ave workspace.

It is intended for code that needs Ave request models, governance payloads,
bridge types and lightweight utilities without depending on heavier runtime
crates.

This crate is free software and is distributed under the `AGPL-3.0-only`
license.

## What it includes

- Ledger event request types
- Governance update payloads
- Bridge request and response models for API communication
- Common utility types such as `Namespace`, `SchemaType` and `ValueWrapper`
- Re-export of `ave-identity` when the `common` feature is enabled

## Features

- `common`: enables the core domain and bridge models
- `value-wrapper`: enables `ValueWrapper`
- `openapi`: derives `utoipa` schemas
- `typescript`: derives TypeScript definitions

Default features enable `common`.

## Basic example

```rust
use ave_common::{CreateRequest, EventRequest, Namespace, SchemaType};
use ave_common::identity::DigestIdentifier;

let request = EventRequest::Create(CreateRequest {
    name: Some("subject".to_string()),
    description: Some("example".to_string()),
    governance_id: DigestIdentifier::default(),
    schema_id: SchemaType::Governance,
    namespace: Namespace::from("demo.root"),
});

assert!(request.is_create_event());
```

## Main modules

- `request`: ledger-facing event payloads
- `governance`: governance change sets, roles and policy payloads
- `bridge`: API-facing request, response and signature types
- `error`: conversion and bridge error types
- `namespace`: hierarchical namespace helper
- `schematype`: schema identifiers and reserved values
- `sink`: flattened event payloads for sink integrations
- `wrapper`: JSON value wrapper with Borsh support

## Notes

- `ValueWrapper` exists to move JSON-compatible data through Borsh boundaries.
- Bridge types are transport-oriented and can be converted to internal types
  through `common::bridge::conversions`.
- When `typescript` is enabled, many public types derive `ts-rs` exports.

## Development

Run the crate tests:

```bash
cargo test -p ave-common
```
