# Pinned build inputs (`ave-common`)

Single source of truth for everything a deterministic contract build
needs besides the toolchain itself. Both the node pipeline
(`ave-core`) and the off-chain gate (`ave-pin`) read these files
through `ave_common::build` — never from copies.

## Files

- `contract.rs` — THE frozen contract source. It is NOT what the
  network builds (the ledger carries arbitrary contract sources).
  Its sole purpose is giving every parity check the SAME input:
  gate builds, CI matrix, pre-flight and external verification all
  compile exactly these bytes. If two parties disagree on a hash,
  this file decides who is right. Shared by all pins until a pin
  freezes its own (same rule as the lockfile below).
- `contract-vN.Cargo.lock` — frozen dependency set, version `N`.
  The node writes it next to the manifest and builds `--locked`;
  the tool does the same. Versions are append-only: a new set is a
  new file, never an overwrite.

## How each file was generated (v1)

Source: decoded from the `EXAMPLE_CONTRACT` fixture (proven to
compile under the contract template), frozen as-is.

```bash
# contract.rs: base64-decoded from the EXAMPLE_CONTRACT fixture,
# byte-exact, frozen as-is.
# contract-v1.Cargo.lock (the template already carries [workspace];
# only a src/lib.rs placeholder is needed for resolution):
mkdir -p /tmp/lockgen/src
cp <sdk>/src/runtime/contract_Cargo.toml /tmp/lockgen/Cargo.toml
echo '// placeholder' > /tmp/lockgen/src/lib.rs
cargo generate-lockfile --manifest-path /tmp/lockgen/Cargo.toml
# → 28 packages, cargo 1.98.1; stored as common/pins/contract-v1.Cargo.lock
```

Recorded as `FrozenLockfile { version: 1, .. }` with provenance in
`common/src/build.rs`, and hashed into each registry entry as
`lock_hash` (blake3 of the file bytes).

## Adding a new version (new deps)

1. Generate the lockfile exactly as above against the new set.
2. Save it as `contract-vN.Cargo.lock` (N = previous + 1).
3. Extend `pin_lockfile()` with the new arm (new pins point at it;
   old pins keep pointing at theirs — that is the point).
4. Update the provenance constant and the registry `lock_hash` of
   affected new entries.
5. The new file must verify: `verify_registry_integrity()` compares
   embedded bytes vs registered hash at node boot and tool startup
   (fail loud). A hand edit without version bump fails here.

## What each file contributes to determinism

| File | Fixes | Without it |
|---|---|---|
| `contract.rs` | same input everywhere (gate parity) | unverifiable disagreements |
| `contract-vN.Cargo.lock` | same dependency versions on every machine and date | drift as registries publish |
| registry `lock_hash` | the file is the registered one | silent swaps |

## Change matrix (dev phase: what to touch when)

| You change | Touch | How you know |
|---|---|---|
| Contract template (`CONTRACT_CARGO_TOML` in SDK) | new pin revision; `ave-pin register` | `audit`: template FAIL per pin |
| SDK `src/` or `Cargo.toml`, no version bump | `ave-pin register` (fills `sdk_source_blake3`); new revision if bytes move | `audit`: sdk-tree FAIL |
| SDK version bump | `ave-pin register` (new `sdk_version`) | `audit`: sdk FAIL |
| Dependencies (new/changed) | freeze `contract-vN+1.Cargo.lock`, new arm in `pin_lockfile()`, new revision | `audit`: lockfile FAIL + builds with `--locked` fail |
| Rust toolchain for a pin | `ave-pin register --toolchain` (new hash) | `audit --rebuild` FAIL |
| Reproducible cargo binary (new backport) | blake3 per arch in the registry `cargo_bins` (`register` copies them into `pin.json`); nodes pick it up via `Config.cargo_bin`, the tool via `AVE_CARGO_BIN` | `audit`: cargo_bins FAIL; node boot fails loud |
| Docker tooling | rebuild image, record new digest in entries + `pin.json` | digest mismatch on verify |
| Anything above uncommitted | commit first | `audit`: uncommitted-changes warn |

`ave-pin audit [--rebuild --toolchain <tc>]` recomputes all of the
above and exits nonzero on any error. Run it before promoting
anything; run it again in a month instead of remembering this file.
