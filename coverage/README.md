# Code Coverage for `ave`

This document describes how to measure code coverage for the `ave` workspace. Please read it in full before running any commands — the "Common Mistakes" section at the end documents errors that are easy to make and hard to debug.

> **Project:** `ave` — an open-source distributed ledger system.  
> **Last measurement:** 2026-05-21  
> **Tool:** [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [The Cargo Wrapper](#2-the-cargo-wrapper)
3. [The `test` Feature](#3-the-test-feature)
4. [Running the Measurements](#4-running-the-measurements)
5. [Aggregating the Results](#5-aggregating-the-results)
6. [Current Results](#6-current-results)
7. [Common Mistakes](#7-common-mistakes)
8. [Technical Notes](#8-technical-notes)

---

## 1. Prerequisites

Install the coverage tool:

```bash
cargo install cargo-llvm-cov
```

---

## 2. The Cargo Wrapper

`cargo-llvm-cov` exports `RUSTC_WRAPPER=cargo-llvm-cov`. This variable is inherited by child processes, including the nested WASM compilations that `ave-core` launches during its test suite. The `wasm32-unknown-unknown` target on the stable toolchain **does not** include `profiler_builtins`, so the nested compilation aborts with:

```
error[E0463]: can't find crate for `profiler_builtins`
```

The fix is to intercept `cargo` on the `PATH` with a wrapper that detects `wasm32-unknown-unknown` builds, strips the coverage-related environment variables, and then forwards the call to the real `cargo` binary.

### Wrapper layout

The wrapper **must** be placed inside a directory named `cargo-wrapper`, and the directory (not the file) must be prepended to `PATH`:

```
coverage/
└── cargo-wrapper/
    └── cargo          ← executable, chmod +x
```

**Before you measure, verify the wrapper:**

```bash
ls -la coverage/cargo-wrapper/cargo
file coverage/cargo-wrapper/cargo
```

The output should say `Bourne-Again shell script` (or similar) and show execute permissions.  
**It must not be a plain file directly under `coverage/`;** `PATH` expects a *directory* containing the executable.

### Wrapper source

The wrapper is shipped in this directory at `cargo-wrapper/cargo`. In short, it does the following:

```bash
#!/bin/bash
if [[ "$*" == *"wasm32-unknown-unknown"* ]]; then
    unset RUSTFLAGS
    unset CARGO_ENCODED_RUSTFLAGS
    unset CARGO_TARGET_DIR
    unset LLVM_PROFILE_FILE
    unset RUSTC_WRAPPER
fi
exec /home/ale/.cargo/bin/cargo "$@"
```

> **Note for other machines:** The `exec` line hard-codes the cargo installation path used when this guide was written. If you are running on a different system, edit `coverage/cargo-wrapper/cargo` and replace the `exec` path with the output of `which cargo` on your machine, or set `REAL_CARGO` and adjust the script accordingly.

---

## 3. The `test` Feature

The crates `ave-core`, `ave-network`, `ave-bridge`, and `ave-http` define a feature named `test` that shortens timeouts and retry intervals in integration tests (from 30–300 s down to 5 s). **If you do not enable it, the `ave-core` integration tests will take >10 min or hang indefinitely.**

* `ave-identity` and `ave-common` **do not** have this feature — do not add it.
* All other crates listed above require it explicitly when measuring coverage.

---

## 4. Running the Measurements

Run all commands from the **workspace root**.  
**Do not use `--lib`** — that skips integration tests and produces a misleadingly low coverage figure.

```bash
WRAPPER="$PWD/coverage/cargo-wrapper"

# 1. ave-identity   (~10 s)
PATH="$WRAPPER:$PATH" cargo llvm-cov --package ave-identity \
  --json --summary-only --output-path /tmp/cov-identity.json

# 2. ave-common     (~10 s)
PATH="$WRAPPER:$PATH" cargo llvm-cov --package ave-common \
  --json --summary-only --output-path /tmp/cov-common.json

# 3. ave-network    (~30 s)
PATH="$WRAPPER:$PATH" cargo llvm-cov --package ave-network --features test \
  --json --summary-only --output-path /tmp/cov-network.json

# 4. ave-core       (~7–8 min)
PATH="$WRAPPER:$PATH" cargo llvm-cov --package ave-core --features test \
  --json --summary-only --output-path /tmp/cov-core.json

# 5. ave-bridge     (~1 min)
PATH="$WRAPPER:$PATH" cargo llvm-cov --package ave-bridge --features test \
  --json --summary-only --output-path /tmp/cov-bridge.json

# 6. ave-http       (~2 min)
PATH="$WRAPPER:$PATH" cargo llvm-cov --package ave-http --features test \
  --json --summary-only --output-path /tmp/cov-http.json
```

> `cargo-llvm-cov` uses `target/llvm-cov-target`, separate from `target/debug`. The first run rebuilds everything; subsequent runs reuse artifacts.

---

## 5. Aggregating the Results

The JSON files produced above contain per-crate summaries. Use the following Python snippet to compute the workspace-wide weighted average:

```python
import json

CRATES = {
    "identity": "/tmp/cov-identity.json",
    "common":   "/tmp/cov-common.json",
    "network":  "/tmp/cov-network.json",
    "core":     "/tmp/cov-core.json",
    "bridge":   "/tmp/cov-bridge.json",
    "http":     "/tmp/cov-http.json",
}

total_lines = 0
total_covered = 0

for name, path in CRATES.items():
    with open(path) as f:
        data = json.load(f)
    for d in data.get("data", []):
        totals = d.get("totals", {}).get("lines", {})
        covered = totals.get("covered", 0)
        count   = totals.get("count", 0)
        pct     = totals.get("percent", 0.0)
        print(f"ave-{name:10s}  {covered:6d}/{count:6d} lines  {pct:6.2f}%")
        total_lines   += count
        total_covered += covered

avg = (total_covered / total_lines * 100) if total_lines else 0
print(f"\nave (weighted average)                {avg:6.2f}%")
```

---

## 6. Current Results

The figures below were obtained with `cargo-llvm-cov` and the functional wrapper, `--features test` enabled where required, and **without `--lib`**.

| Crate            | Lines covered | Total lines | Coverage |
|------------------|--------------:|------------:|---------:|
| `ave-identity`   | 1,180         | 1,442       | **81.83%** |
| `ave-common`     | 1,700         | 2,091       | **81.30%** |
| `ave-network`    | 3,145         | 3,741       | **84.07%** |
| `ave-core`       | 22,448        | 31,658      | **70.91%** |
| `ave-bridge`     | 549           | 1,150       | **47.74%** |
| `ave-http`       | 7,563         | 9,988       | **75.72%** |
| **`ave`**        | —             | —           | **75.55%** |

```
(1180 + 1700 + 3145 + 22448 + 549 + 7563) / (1442 + 2091 + 3741 + 31658 + 1150 + 9988)
= 38585 / 51070 = 75.55%
```

---

## 7. Common Mistakes

1. **Wrapper is a file instead of a directory.**  
   `PATH` requires a directory. If `coverage/cargo-wrapper` is a plain file, `cargo` will not be found there and the wrapper will do nothing. `ave-core` tests will either fail with `profiler_builtins` or, worse, appear to pass but report `--lib` coverage (much lower).

2. **Using `--lib`.**  
   `--lib` only runs unit tests inside the library, skipping integration tests (`tests/*.rs`). For `ave-core` this is the difference between ~40% and ~71% coverage.

3. **Forgetting `--features test`.**  
   Without it, production timeouts (30–300 s) are active. The `ave-core` integration tests will not finish in a reasonable time.

4. **Running `cargo test --workspace`.**  
   This is prohibited in this workspace. Always measure crate by crate.

5. **Relying on `cargo-tarpaulin` or `kcov`.**  
   `cargo-tarpaulin --engine Ptrace` causes segfaults in `ave-core`. `cargo-tarpaulin --engine Llvm` has the same `RUSTC_WRAPPER` issue as `cargo-llvm-cov`. `kcov` is not installed. The only validated tool is `cargo-llvm-cov` + wrapper.

---

## 8. Technical Notes

* **Do not modify production code** to adapt it to coverage tools. The wrapper is the correct interface.
* **Do not clear `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`** thinking that fixes the problem. `cargo-llvm-cov` injects coverage via `RUSTC_WRAPPER`, not via those variables.
* **Do not clear `CARGO_TARGET_DIR`** thinking it avoids deadlocks. That was a secondary symptom; the root cause was always `RUSTC_WRAPPER`.
