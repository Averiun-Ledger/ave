# ave-network

Peer-to-peer networking layer for the Ave ledger stack.

`ave-network` provides the libp2p-based transport and routing runtime used by Ave nodes. It packages discovery, request-response messaging, peer monitoring, connection policies, and network sizing into a single crate that higher-level runtimes can embed directly.

This crate is meant for consumers that need the network subsystem without pulling in the full `ave-core` runtime.

## What this crate provides

- `NetworkWorker<T>`, the main event loop that drives the network runtime
- `NetworkService`, the command interface used by the rest of the application
- `Config`, `RoutingConfig`, and `ControlListConfig` for network setup
- libp2p transport composition with TCP, DNS, Noise, Yamux, Identify, Kademlia, and request-response
- node role modelling through `NodeType`
- monitoring integration through the `Monitor` actor
- metrics registration hooks
- host-aware sizing through `MachineSpec` and `MachineProfile`

## When to use `ave-network`

Use `ave-network` when you need:

- Ave-compatible peer discovery and messaging
- a reusable libp2p worker that can be embedded in another runtime
- control over the network layer independently of the full ledger runtime

If you need the complete node stack, use `ave-core` instead.

## Installation

```toml
[dependencies]
ave-network = "0.9.0"
```

## Core concepts

### `NetworkWorker<T>`

`NetworkWorker<T>` is the main runtime component. It owns the libp2p swarm, receives commands, processes swarm events, tracks peer state, and coordinates retries and buffering.

### `NetworkService`

`NetworkService` is the application-facing handle used to send commands into the worker. It is the bridge between the rest of the runtime and the network event loop.

### `Config`

`Config` defines:

- safe mode (`safe_mode`)
- node role (`Bootstrap`, `Addressable`, or `Ephemeral`)
- listen and external addresses
- boot nodes
- routing settings
- control-list settings
- memory-based connection limits
- message and queue byte caps

### `MachineSpec`

`MachineSpec` and `MachineProfile` let the network backend tune itself to a target machine class. If you do not provide one, the crate auto-detects host RAM and CPU parallelism.

## Configuration example

```toml
[network]
safe_mode = false
node_type = "bootstrap"
listen_addresses = ["/ip4/0.0.0.0/tcp/4001"]
external_addresses = ["/dns4/node.example.com/tcp/4001"]

[[network.boot_nodes]]
peer_id = "12D3KooW..."
address = ["/dns4/bootstrap.example.com/tcp/4001"]

[network.memory_limits]
type = "percentage"
value = 0.8
```

The memory limit policy can also be disabled or configured as an absolute MB threshold.

## Safe mode

`Config::safe_mode` starts the networking layer in an isolated maintenance mode.

In this mode the worker still starts, listens, and reports `Running`, but it:

- does not bootstrap or dial peers
- does not send outbound application messages
- does not deliver inbound application traffic to the runtime
- closes or discards network traffic instead of participating normally

This is useful when a higher-level runtime wants local queries and maintenance
operations without joining the peer-to-peer network.

## Embedding example

```rust,ignore
use ave_common::identity::{KeyPair, KeyPairAlgorithm};
use ave_network::{Config, NetworkWorker, NodeType};
use tokio_util::sync::CancellationToken;

fn build_config() -> Config {
    Config::new(
        NodeType::Bootstrap,
        vec!["/ip4/0.0.0.0/tcp/4001".to_string()],
        Vec::new(),
        Vec::new(),
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keys = KeyPair::generate(KeyPairAlgorithm::Ed25519)?;
    let config = build_config();
    let graceful = CancellationToken::new();
    let crash = CancellationToken::new();

    let _worker = NetworkWorker::<()>::new(
        &keys,
        config,
        None,
        graceful,
        crash,
        None,
        None,
    )?;

    Ok(())
}
```

In a real application, the worker is polled asynchronously and connected to the rest of the runtime through `NetworkService`.

## Network roles

- `Bootstrap`: intended to be reachable and participate in peer discovery
- `Addressable`: intended to accept inbound connectivity while operating as a regular node
- `Ephemeral`: intended for short-lived or non-addressable participants

## Message flow

At a high level:

- the application sends commands through `NetworkService`
- `NetworkWorker` translates those commands into libp2p actions
- inbound events are processed and optionally forwarded to helper components
- monitor actors receive network state changes for runtime visibility

The worker also keeps bounded per-peer and global pending queues so disconnections do not turn into unbounded memory growth.

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `test` | No | Internal development feature used by this crate's tests |

## Ecosystem fit

`ave-network` sits below `ave-core` and above the shared types from `ave-common`. It is the right level if you want the Ave networking behavior without the higher-level request, governance, and persistence machinery.
