# ave-build

Deterministic contract compilation shared by the node (`ave-core`)
and the off-chain pin tooling (`ave-toolchain-pins`): one
implementation of materializing a contract build project
(manifest, source, frozen lockfile, rendered cargo config),
running the cargo build with the selected toolchain, and
attesting which toolchain produced the bytes. Callers own
everything else (staging, anchors, quorum, CLI, pins).

Scalar rules (target, epoch, frozen inputs) stay in
`ave_common::build`; the procedure lives here. See `src/lib.rs`.

## Key API

- `BuildRequest` — everything a build needs: decoded source,
  templates, frozen lockfile, target/vendor/cargo-home dirs,
  toolchain selector, `CargoProgram`, sysroot data, offline/locked
  flags, timeout. Paths travel as given (relative or absolute);
  the vendor dir must be relative to the build dir — the config
  writes it verbatim and an absolute path would bake the machine
  into every build.
- `CargoProgram::{System, Rustup, Pinned}` — which cargo runs:
  ambient (pre-pins behavior), `rustup run <toolchain>` isolation,
  or an explicit binary with `RUSTC` resolved to the toolchain.
  Only `Pinned` with the registry-blessed binary (rust-lang/
  cargo#17522 backport) gives cross-architecture byte identity;
  see `Config.cargo_bin` on the node and `AVE_CARGO_BIN` in the
  tool.
- `query_sysroot` / `rustc_version` / `toolchain_fingerprint` —
  selected-toolchain attestations sharing one cached probe per
  process (toolchains are static per boot, no hot-swap).
- `prepare_project` / `run_cargo_build` / `build_contract_wasm`
  — materialize, build (600 s default via `BUILD_TIMEOUT_SECS`,
  whole process group reaped on timeout), load the wasm.
- `MAX_SOURCE_BYTES` (1 MiB, same bound as the node intake),
  stderr capture capped at 64 KiB with endless drain.

## Consumers

- Node production + named-toolchain test builds
  (`core/src/compilation/support.rs`), the test-pool service
  (`core/src/compilation/service.rs`, no lockfile: arbitrary test
  sources have no frozen set).
- `ave-pin build/verify/register`
  (`ave-contracts/ave-toolchain-pins/src/build.rs`).
