//! Deterministic contract-build rules: the single source of truth
//!
//! shared by the node pipeline (`ave-core`) and the off-chain pin
//! tooling (`ave-toolchain-pins`). Same rules in, same bytes out, on
//! any architecture with the pinned toolchain.
//!
//! What shapes identical bytes (all enforced by consumers of this
//! module):
//! - the toolchain itself (registry pin in `super::governance`),
//! - the frozen dependency set ([`pin_lockfile`], built `--locked`),
//! - the target triple ([`WASM_TARGET`]),
//! - no timestamps ([`SOURCE_DATE_EPOCH`], plus `strip = true` and
//!   `--remap-path-prefix` in the contract cargo config, which the
//!   template owns),
//! - the fixed release profile below (opt-level, LTO, codegen-units,
//!   panic, strip — mirrored in the contract `Cargo.toml` template;
//!   keep both in sync).

use std::path::{Path, PathBuf};

/// WASM target every contract build must use.
pub const WASM_TARGET: &str = "wasm32-unknown-unknown";

/// Pinned `SOURCE_DATE_EPOCH` for every contract build: no wall-clock
/// input may shape artifacts. Cargo forwards it to build scripts;
///
/// `rustc` itself embeds no timestamps once paths are remapped and
/// debug info stripped, so this is belt-and-braces, not the mechanism.
pub const SOURCE_DATE_EPOCH: &str = "0";

/// Normative release profile, mirrored in the contract `Cargo.toml`
/// template owned by `ave-contract-sdk` (`CONTRACT_CARGO_TOML`).
/// Change both together or not at all.
pub mod profile {
    /// Optimization level.
    pub const OPT_LEVEL: u8 = 3;
    /// Link-time optimization.
    pub const LTO_FAT: bool = true;
    /// Single codegen unit (parallel codegen partitions output).
    pub const CODEGEN_UNITS: u8 = 1;
    /// Abort on panic (no unwinding tables leaking host layout).
    pub const PANIC_ABORT: bool = true;
    /// Strip debug info and symbols (paths and buildIds diverge).
    pub const STRIP_SYMBOLS: bool = true;
}

/// A frozen dependency set: versioned file plus its provenance, so
/// anyone can tell WHICH set a pin builds with and where it came
/// from. New sets add a file (`contract-vN.Cargo.lock`) and an arm
///
/// below — files are never overwritten, versions never reused.
#[derive(Debug, Clone, Copy)]
pub struct FrozenLockfile {
    /// Monotonic version, 1-based. Bumped only by freezing a new set.
    pub version: u32,
    /// The `Cargo.lock` contents the pin builds with (`--locked`).
    pub content: &'static str,
    /// How it was generated (tool, template, rustc, date). Any hand
    /// edit without bumping the version is corruption.
    pub provenance: &'static str,
}

/// Frozen dependency set for a registry pin. `None` means "resolve
///
/// fresh", the pre-pins behavior kept for pins without a frozen set.
/// A pin with a frozen set always builds with `--locked` against it,
/// so dependency versions can never drift across machines or time.
/// Versions resolve through the registry table (one source), files
/// below are append-only.
pub fn pin_lockfile(id: &str) -> Option<FrozenLockfile> {
    let version = crate::registry::pin_lockfile_version(id)?;
    let (content, provenance) = match version {
        1 => (
            include_str!("../pins/contract-v1.Cargo.lock"),
            "cargo-generate-lockfile/1.98.1 template=CONTRACT_CARGO_TOML+chrono sdk=0.8.0 date=2026-10-18",
        ),
        _ => return None,
    };
    Some(FrozenLockfile {
        version,
        content,
        provenance,
    })
}

/// Self-verification: every registry entry naming a lock hash must
/// match the embedded file byte for byte. Call once at boot, fail
///
/// loud on mismatch — a swapped file must never silently resolve
/// different dependencies.
pub fn verify_registry_integrity() -> Result<(), String> {
    // IDs derived from the registry itself: adding a pin needs no
    // change here, only its entry + file arms above.
    for id in crate::governance::registry_ids() {
        let entry = crate::governance::toolchain_info(id)
            .ok_or_else(|| format!("registry entry {id} missing"))?;
        if entry.lock_hash.is_empty() {
            continue;
        }
        let file = pin_lockfile(id)
            .ok_or_else(|| {
                format!("registry entry {id} names no embedded lockfile")
            })?
            .content;
        let actual = blake3_hex(file.as_bytes());
        if actual != entry.lock_hash {
            return Err(format!(
                "lockfile for {id} does not match registry hash"
            ));
        }
    }
    Ok(())
}

/// blake3 hex helper shared by registry self-verification and the
/// off-chain gate (same function, same bytes, both sides).
pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// The shared frozen set itself, for tools that provision a new pin
/// reusing the current dependencies (the common case: new rustc, same
/// deps). New dependency sets get their own versioned file + match
///
/// arm in `pin_lockfile` instead — never an overwrite.
pub const fn shared_contract_lockfile() -> &'static str {
    include_str!("../pins/contract-v1.Cargo.lock")
}

/// The shared frozen source itself, for tools provisioning a new pin
/// reusing the current contract (the common case). New sources get
/// their own file + match arm in `pin_contract_source` instead.
pub const fn shared_contract_source() -> &'static str {
    include_str!("../pins/contract.rs")
}

/// Frozen contract source a pin builds. Shared until a pin freezes
///
/// its own: the tool and the node read it from here, never from a
/// copy, so gate hashes and ledger bytes can not drift apart by
/// source skew. Versions resolve through the registry table; unknown
/// pins get `None` (callers fall back to the shared source
/// explicitly, never silently).
pub fn pin_contract_source(id: &str) -> Option<&'static str> {
    match crate::registry::pin_source_version(id) {
        Some(1) => Some(shared_contract_source()),
        _ => None,
    }
}

/// `src/rust` under a rustc sysroot: the root the build config
/// remaps to `/rustc/<commit>`, so absolute sysroot paths never
/// shape artifacts. One function so the node pipeline and the
///
/// off-chain gate can never remap different roots.
pub fn rust_src_dir(sysroot: &Path) -> PathBuf {
    sysroot.join("lib").join("rustlib").join("src").join("rust")
}

/// The placeholders sit inside quoted TOML strings: escape values so
/// paths with quotes or backslashes can not break the manifest
/// syntax (or, when paths differ per machine, break determinism
/// across compilers).
fn escape_toml(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Renders the contract cargo config from the SDK template with
/// local paths substituted and the vendored-sources section appended
/// when a vendor dir is given. THE single renderer for the node
/// pipeline (`ave-core`) and the off-chain gate (`ave-pin`): same
/// inputs in, byte-identical config out.
///
/// `vendor_dir` must be absolute and lexically clean (see
/// `absolute_vendor_dir`): cargo resolves it verbatim into the
/// crate paths rustc records, and the `{vendor}` remap below only
/// matches that exact prefix. A relative vendor dir would resolve
/// against the build directory at compile time and bake the
/// machine-specific build root — including the random staging
/// suffix — into every artifact. Without a vendor dir the
/// `{vendor}` remap line is dropped so no placeholder leaks.
pub fn render_contract_cargo_config(
    template: &str,
    target_dir: &Path,
    vendor_dir: Option<&Path>,
    cargo_home: &Path,
    rust_src: &Path,
    rustc_commit: &str,
) -> String {
    // Template placeholders are built programmatically: a `{...}`
    // literal here would trip the formatting-args lint while being
    // exactly what the template needs.
    fn pattern(name: &str) -> String {
        format!("{{{name}}}")
    }
    let mut config = template.to_owned();
    if vendor_dir.is_none() {
        let needle = pattern("vendor");
        let mut kept = String::new();
        for line in config.lines() {
            if !line.contains(&needle) {
                kept.push_str(line);
                kept.push('\n');
            }
        }
        config = kept;
    }
    config = config.replace(
        &pattern("target_dir"),
        &escape_toml(&target_dir.to_string_lossy()),
    );
    config = config.replace(
        &pattern("cargo_home"),
        &escape_toml(&cargo_home.to_string_lossy()),
    );
    config = config.replace(
        &pattern("rust_src"),
        &escape_toml(&rust_src.to_string_lossy()),
    );
    config =
        config.replace(&pattern("rustc_commit"), &escape_toml(rustc_commit));
    if let Some(vendor_dir) = vendor_dir {
        config = config.replace(
            &pattern("vendor"),
            &escape_toml(&vendor_dir.to_string_lossy()),
        );
        config.push_str(&format!(
            "\n[net]\noffline = true\n\n[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"{}\"\n",
            escape_toml(&vendor_dir.to_string_lossy())
        ));
    }
    config
}

/// Lexically clean a path (`..`/`.` resolved, no filesystem
/// access): the vendor remap only matches the exact prefix cargo
/// records, so the config must carry the normalized form.
fn normalize_lexically(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push("/");
    }
    out
}

/// Absolute vendor directory for a build: `<root>/vendor`,
/// lexically normalized, for the cargo config above. The absolute
/// form is what cargo records into crate paths, and the `{vendor}`
/// remap rewrites exactly that prefix to `/vendor` — so artifacts
/// never carry the machine-specific root or the random staging
/// suffix. `None` when the build dir is not under `root` — then no
/// vendor section is emitted. Callers check the dir exists first
/// (same as before: no vendor on disk, no vendor section).
pub fn absolute_vendor_dir(build_dir: &Path, root: &Path) -> Option<PathBuf> {
    build_dir.strip_prefix(root).ok()?;
    if build_dir == root {
        return None;
    }
    Some(normalize_lexically(&root.join("vendor")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The single renderer is pinned: node and tool can not drift
    /// apart without this failing. Placeholder substitution, TOML
    /// escaping and the vendor section are consensus-adjacent — any
    /// change here is a new pin revision, never a silent edit.
    #[test]
    fn render_contract_cargo_config_is_stable() {
        let template = "[build]\ntarget-dir = \"{target_dir}\"\n\
            [target.x]\nremap = \"{cargo_home}|{rust_src}|{rustc_commit}|{vendor}\"\n";
        let rendered = render_contract_cargo_config(
            template,
            Path::new(".build-target"),
            Some(Path::new("/data/contracts/vendor")),
            Path::new("/root/.cargo-home"),
            Path::new("/rustup/sysroot/lib/rustlib/src/rust"),
            "abc123",
        );
        assert_eq!(
            rendered,
            "[build]\ntarget-dir = \".build-target\"\n\
            [target.x]\nremap = \"/root/.cargo-home|/rustup/sysroot/lib/rustlib/src/rust|abc123|/data/contracts/vendor\"\n\
            \n[net]\noffline = true\n\n[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"/data/contracts/vendor\"\n"
        );
        // No vendor section and no leftover placeholder without a vendor dir.
        let rendered = render_contract_cargo_config(
            template,
            Path::new(".build-target"),
            None,
            Path::new("/root/.cargo-home"),
            Path::new("/rustup/sysroot/lib/rustlib/src/rust"),
            "abc123",
        );
        assert!(!rendered.contains("vendored-sources"));
        assert!(!rendered.contains("{vendor}"));
        // Hostile paths can not break the TOML syntax.
        let rendered = render_contract_cargo_config(
            template,
            Path::new(".build-target"),
            Some(Path::new("/data/ven\"dor")),
            Path::new("/ro\\ot"),
            Path::new("/rust"),
            "abc123",
        );
        assert!(rendered.contains(r#"directory = "/data/ven\"dor""#));
        assert!(rendered.contains(r#"/ro\\ot|/rust|abc123|/data/ven\"dor"#));
    }

    /// Absolute vendor dir under the root whatever the build depth;
    /// outside the root (or the root itself) there is none.
    #[test]
    fn absolute_vendor_dir_points_at_root() {
        assert_eq!(
            absolute_vendor_dir(
                Path::new("/data/contracts/scratch-1"),
                Path::new("/data/contracts")
            ),
            Some(PathBuf::from("/data/contracts/vendor"))
        );
        assert_eq!(
            absolute_vendor_dir(
                Path::new("/data/work/contracts/job-1"),
                Path::new("/data/work")
            ),
            Some(PathBuf::from("/data/work/vendor"))
        );
        assert_eq!(
            absolute_vendor_dir(
                Path::new("/data/contracts"),
                Path::new("/data/contracts")
            ),
            None
        );
        assert_eq!(
            absolute_vendor_dir(
                Path::new("/elsewhere/build"),
                Path::new("/data/contracts")
            ),
            None
        );
        // Lexical cleanup, no filesystem access.
        assert_eq!(
            absolute_vendor_dir(
                Path::new("/data/contracts//scratch-1"),
                Path::new("/data/contracts/")
            ),
            Some(PathBuf::from("/data/contracts/vendor"))
        );
    }
}
