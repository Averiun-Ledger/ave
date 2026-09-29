//! Toolchain registry: entries are PROMOTED here, never invented.
//!
//! New pins arrive via `ave-pin register` snippet (human paste,
//! additive only) after both architectures verify; `refresh-all.sh`
//! maintains ONLY the `builder_image` values (regex replace with
//! count guard — anything else touched fails the run). Hand edits
//! outside `builder_image` will be overwritten or flagged by audit.

//! Rules (normative, see plan):
//! - Additive only: never edit or remove an entry, old events keep
//!   verifying against it. ANY component change (rustc, SDK,
//!   lockfile, cargo config) defines a NEW pin.
//! - ID rule: `rust-<rustc>_sdk-<sdk>_<target>`, exact versions, no
//!   ranges. Same triple with a new lockfile takes a `-rN` suffix.
//!   IDs are never reused.
//! - `registry_ids()` and `toolchain_info()` always agree: both
//!   derive from `PIN_REGISTRY` below, and `refresh-all.sh`
//!   aborts unless every entry has a builder_image. Adding a pin
//!   extends `PIN_IDS` and appends one `PinRecord` (plus the frozen
//!   files new versions need); anything else breaks tooling loudly
//!   (audit + count guards).
//!
//! What breaks what (hash impact):
//! - New rustc version → new ID, new expected_wasm, new image.
//!   Old entries: untouched.
//! - SDK sources/manifest touched → new `sdk_source_blake3`,
//!   new expected_wasm for EVERY pin (rebuild all), possibly new
//!   lockfile if deps changed.
//! - Template (`CONTRACT_CARGO_TOML`) touched → new
//!   `cargo_config_hash` in every entry + new expected_wasm
//!   everywhere: in practice a new pin revision for all.
//! - Lockfile touched → new `lock_hash` + new expected_wasm +
//!   new file `contract-vN.Cargo.lock` + new arm in `pin_lockfile()`.
//! - Docker tooling touched → new image digest; `builder_image`
//!   re-recorded via refresh-all.sh (annotative only, never voted).
//!
//! Generation log lives in
//! `ave-toolchain-pins/REGISTRY_LOG.md` (one entry per promotion).

use super::governance::ToolchainInfo;

/// Every registered pin ID, in one place so tooling (audit, CI)
/// iterates exactly what the network enforces. Table entries below
/// reference these positions (`PIN_IDS[0]`, ...): adding a pin extends
/// this list AND appends one `PinRecord` — never in only one side.
const PIN_IDS: &[&str] =
    &["rust-1.95.0_sdk-0.8.0_wasm32", "rust-1.98.1_sdk-0.8.0_wasm32"];

pub fn registry_ids() -> &'static [&'static str] {
    PIN_IDS
}

/// One registry row: the single source of truth for a pin. The ID
/// must be the matching `PIN_IDS` position; frozen inputs are
/// versions into `common/pins/` resolved by `crate::build`
/// (`None` = resolve fresh, the pre-pins behavior).
pub struct PinRecord {
    pub id: &'static str,
    pub info: ToolchainInfo,
    pub lockfile_version: Option<u32>,
    pub source_version: Option<u32>,
}

static PIN_REGISTRY: &[PinRecord] = &[
    PinRecord {
        id: PIN_IDS[0],
        info: ToolchainInfo {
            rustc_version: "1.95.0",
            cargo_config_hash: "10ed106c093be78c7d13394e01b78904155ef70e7e74dc9ce8b69f9cd40f4bea",
            sdk_version: "0.8.0",
            lock_hash: "995560fd74456da3cf8d795aedb01dcf70c5cbfea8dd6c3ac9ed076d27380a6b",
            builder_image: "averiun/ave-tools@sha256:00401caa6f1e220153229eda04a6a537c8f3db5f2b2af9349f96ac1e3333dcbc",
        },
        lockfile_version: Some(1),
        source_version: Some(1),
    },
    PinRecord {
        id: PIN_IDS[1],
        info: ToolchainInfo {
            rustc_version: "1.98.1",
            cargo_config_hash: "10ed106c093be78c7d13394e01b78904155ef70e7e74dc9ce8b69f9cd40f4bea",
            sdk_version: "0.8.0",
            lock_hash: "995560fd74456da3cf8d795aedb01dcf70c5cbfea8dd6c3ac9ed076d27380a6b",
            builder_image: "averiun/ave-tools@sha256:00401caa6f1e220153229eda04a6a537c8f3db5f2b2af9349f96ac1e3333dcbc",
        },
        lockfile_version: Some(1),
        source_version: Some(1),
    },
];

/// Closed toolchain registry: entries are PROMOTED here, never
/// invented. Content verified 2026-09-28 (both pins re-measured by
/// `ave-pin`, both architectures, hashes match).
pub fn toolchain_info(id: &str) -> Option<ToolchainInfo> {
    PIN_REGISTRY.iter().find(|entry| entry.id == id).map(|entry| entry.info)
}

/// Frozen lockfile version for a pin (`None` = unknown pin or fresh
/// resolve). Crate-internal: `crate::build` turns versions into files.
pub(crate) fn pin_lockfile_version(id: &str) -> Option<u32> {
    PIN_REGISTRY
        .iter()
        .find(|entry| entry.id == id)?
        .lockfile_version
}

/// Frozen source version for a pin (`None` = unknown pin or shared
/// fallback). Crate-internal, like `pin_lockfile_version`.
pub(crate) fn pin_source_version(id: &str) -> Option<u32> {
    PIN_REGISTRY
        .iter()
        .find(|entry| entry.id == id)?
        .source_version
}
