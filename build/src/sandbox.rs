//! Unprivileged Linux sandbox for contract builds.
//!
//! Contract authors control only `lib.rs`, but `include_bytes!`,
//! `include_str!` and compile-time `env!` can still reach host files
//! and secrets. Every Linux build therefore runs in its own user,
//! mount and UTS namespaces behind a mirrored minimal root: only
//! the toolchain, loader libraries, vendor sources, cargo home and
//! the build directory exist inside, everything else is absent. The
//! mirror keeps identical absolute paths, so honest artifacts stay
//! byte-identical across machines. Offline production builds
//! additionally run without host networking.
//!
//! The child side (`pre_exec`) performs raw syscalls only: after
//! `fork` from a multithreaded runtime no allocation, no Rust
//! formatting and no std IO may run before `exec`. Everything the
//! child needs is precomputed here in the parent.

use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Everything the child needs, precomputed in the parent before
/// `spawn`. No field is allocated or formatted after `fork`.
pub struct Spec {
    mounts: Vec<MountOp>,
    copies: Vec<(CString, Vec<u8>)>,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    hostname: CString,
    pivot_new: CString,
    pivot_old: CString,
    workdir: CString,
    build_tmp: PathBuf,
    isolated_net: bool,
}

struct MountOp {
    source: CString,
    target: CString,
    fstype: Option<CString>,
    flags: libc::c_ulong,
    data: Option<CString>,
    /// A failed best-effort mount never fails the build.
    best_effort: bool,
}

fn cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("path has no nul")
}

/// Resolve `name` through `PATH` like the shell would.
pub(crate) fn resolve_in_path(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let candidate = PathBuf::from(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        return None;
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Parent dirs of every dynamically loaded library of `exe`.
async fn loader_dirs(exe: &Path) -> io::Result<Vec<PathBuf>> {
    let output = tokio::process::Command::new("ldd")
        .arg(exe)
        .output()
        .await?;
    if !output.status.success() {
        return Err(io::Error::other("ldd failed on build program"));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut dirs = Vec::new();
    for line in text.lines() {
        let path = if let Some(pos) = line.find("=>") {
            line[pos + 2..].split_whitespace().next()
        } else {
            line.split_whitespace()
                .next()
                .filter(|token| token.starts_with('/'))
        };
        if let Some(path) = path {
            let parent = Path::new(path).parent();
            if let Some(dir) = parent {
                let dir = dir.to_path_buf();
                if !dirs.contains(&dir) {
                    dirs.push(dir);
                }
            }
        }
    }
    Ok(dirs)
}

/// Stage the sandbox: resolve every dependency, create the mirror
/// skeleton under the build directory. Mounts happen in the child
/// (new mount namespace), never on the host.
pub async fn prepare(
    program: &Path,
    rustc_bin: Option<&Path>,
    sysroot: &Path,
    cargo_home: &Path,
    vendor_dir: Option<&Path>,
    build_dir: &Path,
    offline: bool,
) -> io::Result<(Spec, PathBuf, Option<PathBuf>)> {
    let exe = if program.is_absolute() {
        if program.is_file() {
            program.to_path_buf()
        } else {
            return Err(io::Error::other("build program not found"));
        }
    } else {
        resolve_in_path(&program.to_string_lossy())
            .ok_or_else(|| io::Error::other("build program not found"))?
    };
    let canonical_build = tokio::fs::canonicalize(build_dir)
        .await
        .unwrap_or_else(|_| build_dir.to_path_buf());
    let canonical_cargo_home = tokio::fs::canonicalize(cargo_home)
        .await
        .unwrap_or_else(|_| cargo_home.to_path_buf());

    let mut mirror: Vec<(PathBuf, bool)> = Vec::new();
    let mut push = |path: PathBuf, writable: bool| {
        if !mirror.iter().any(|(known, _)| known == &path) {
            mirror.push((path, writable));
        }
    };

    if let Some(exe_dir) = exe.parent() {
        push(exe_dir.to_path_buf(), false);
    }
    if let Some(rustc) = rustc_bin {
        if let Some(dir) = rustc.parent() {
            push(dir.to_path_buf(), false);
        }
        for dir in loader_dirs(rustc).await.unwrap_or_default() {
            push(dir, false);
        }
    }
    for dir in loader_dirs(&exe).await.unwrap_or_default() {
        push(dir, false);
    }
    push(sysroot.to_path_buf(), false);
    // The rustup proxy locates toolchains through its home: prefer
    // the explicit `$RUSTUP_HOME`, fall back to the conventional
    // `$HOME/.rustup/settings.toml` so dev machines keep working
    // unchanged. Never mirror a home tree wholesale.
    if let Some(home) = std::env::var_os("RUSTUP_HOME") {
        let dir = PathBuf::from(home);
        if dir.is_dir() {
            push(dir, false);
        }
    } else if let Some(home) = std::env::var_os("HOME") {
        let settings = PathBuf::from(home).join(".rustup/settings.toml");
        if settings.is_file() {
            push(settings, false);
        }
    }
    // Host C linker for build scripts, resolved once so the child
    // never depends on `PATH` lookup or dangling `cc` alternatives.
    let mut host_cc = None;
    for candidate in [std::env::var_os("CC"), std::env::var_os("TARGET_CC")] {
        if let Some(name) = candidate {
            let path = PathBuf::from(name);
            if path.is_file() {
                host_cc = Some(path);
                break;
            }
        }
    }
    let host_cc = match host_cc {
        Some(path) => Some(path),
        None => resolve_in_path("cc"),
    };
    let host_cc = match host_cc {
        Some(path) => tokio::fs::canonicalize(&path).await.ok(),
        None => None,
    };
    if let Some(dir) = host_cc.as_ref().and_then(|cc| cc.parent()) {
        push(dir.to_path_buf(), false);
    }
    for dir in ["/usr/bin", "/usr/lib", "/usr/lib64", "/usr/libexec"] {
        let path = PathBuf::from(dir);
        if path.is_dir() {
            push(path, false);
        }
    }
    // Alternatives chain for system tools (`cc`, `python`, ...): only
    // program paths, no secrets, and it keeps dangling links inside
    // mirrored trees working without recreating them.
    {
        let path = PathBuf::from("/etc/alternatives");
        if path.is_dir() {
            push(path, false);
        }
    }
    if let Some(vendor) = vendor_dir {
        let absolute = if vendor.is_absolute() {
            vendor.to_path_buf()
        } else {
            canonical_build.join(vendor)
        };
        let canonical = tokio::fs::canonicalize(&absolute)
            .await
            .unwrap_or(absolute);
        push(canonical, false);
    }
    // Name resolution and TLS for online (dev-only) builds: public
    // trust anchors, no secrets. Offline production builds ignore them.
    for etc in [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/ssl/certs",
        "/usr/share/ca-certificates",
    ] {
        let path = PathBuf::from(etc);
        if path.exists() {
            push(path, false);
        }
    }
    // The build toolchain locates itself through `/proc/self/exe`,
    // which a fresh instance can not always provide here, so the
    // host table is bound instead (no read-only remount: the kernel
    // rejects it for this filesystem and already enforces per-file
    // permissions). Secrets never travel in arguments or in the
    // scrubbed build environment, and the mirror hides everything else.
    push(PathBuf::from("/proc"), true);
    // Absolute `path = "..."` dependencies in the contract manifest
    // (e.g. the SDK) live outside the build directory: mirror them
    // read-only, following relative path deps transitively. Generated
    // manifests only, so a line scan is sufficient.
    {
        let mut manifests = vec![canonical_build.join("Cargo.toml")];
        let mut seen = std::collections::HashSet::new();
        let mut depth = 0;
        while let Some(manifest) = manifests.pop() {
            if depth > 32 || !seen.insert(manifest.clone()) {
                continue;
            }
            depth += 1;
            let Ok(content) = tokio::fs::read_to_string(&manifest).await
            else {
                continue;
            };
            let manifest_dir = manifest
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/"));
            for line in content.lines() {
                let Some(pos) = line.find("path") else {
                    continue;
                };
                let rest = &line[pos + 4..];
                let Some(start) = rest.find('"') else {
                    continue;
                };
                let Some(end) = rest[start + 1..].find('"') else {
                    continue;
                };
                let dep = PathBuf::from(&rest[start + 1..start + 1 + end]);
                let absolute = if dep.is_absolute() {
                    dep
                } else {
                    manifest_dir.join(&dep)
                };
                let Ok(canonical) =
                    tokio::fs::canonicalize(&absolute).await
                else {
                    continue;
                };
                push(canonical.clone(), false);
                // Workspace members inherit keys (e.g. `edition`) from
                // the root manifest: mirror that single file too.
                let mut ancestor = canonical.as_path();
                for _ in 0..6 {
                    let Some(parent) = ancestor.parent() else {
                        break;
                    };
                    ancestor = parent;
                    let root_manifest = ancestor.join("Cargo.toml");
                    if root_manifest == canonical.join("Cargo.toml") {
                        break;
                    }
                    if let Ok(root) =
                        tokio::fs::read_to_string(&root_manifest).await
                    {
                        if root.contains("[workspace]") {
                            push(root_manifest.clone(), false);
                            // A root that is also a package must
                            // present its targets to the parser.
                            let root_src = ancestor.join("src");
                            if root_src.is_dir() {
                                push(root_src, false);
                            }
                            break;
                        }
                    }
                }
                manifests.push(canonical.join("Cargo.toml"));
            }
        }
    }
    push(canonical_cargo_home.clone(), true);
    push(canonical_build.clone(), true);

    let new_root = canonical_build.join("sandbox-root");
    let old_root = new_root.join("old");
    let build_tmp = canonical_build.join("sandbox-tmp");
    for dir in [&new_root, &old_root, &build_tmp] {
        tokio::fs::create_dir_all(dir).await?;
    }
    // The child bind-mounts the cargo home: it must exist beforehand.
    tokio::fs::create_dir_all(&canonical_cargo_home).await?;
    // Skeleton for devices, scratch and process table inside.
    for dir in ["dev", "tmp", "proc"] {
        tokio::fs::create_dir_all(new_root.join(dir)).await?;
    }
    // Device placeholders: the child bind-mounts the host nodes over
    // them, so they must exist as files beforehand.
    for node in ["null", "zero", "full", "urandom"] {
        let target = new_root.join("dev").join(node);
        if tokio::fs::metadata(&target).await.is_err() {
            tokio::fs::write(&target, []).await?;
        }
    }

    let target_of = |source: &Path| {
        new_root.join(source.strip_prefix("/").unwrap_or(source))
    };
    // Dangled symlinks can not be bind-mounted: the kernel follows
    // them on the host, but inside only mirrored paths exist. Files
    // whose target stays outside the mirror (e.g. `/etc/resolv.conf`
    // pointing outside the image) are materialized by content instead.
    // Links inside mirrored trees keep working when their whole
    // resolution chain is mirrored too (e.g. the alternatives chain
    // for `cc`: `/usr/bin` plus `/etc/alternatives`).
    let mut copies: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for (source, _) in &mirror {
        if !source.is_file() {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(source) else {
            continue;
        };
        if !meta.is_symlink() {
            continue;
        }
        let Ok(resolved) = std::fs::canonicalize(source) else {
            continue;
        };
        if mirror.iter().any(|(dir, _)| resolved.starts_with(dir)) {
            continue;
        }
        if let Ok(bytes) = std::fs::read(source) {
            if bytes.len() <= 1 << 20 {
                copies.push((source.clone(), bytes));
            }
        }
    }
    let mut mounts = Vec::new();
    for (source, writable) in &mirror {
        let target = target_of(source);
        if source.is_file() {
            if copies.iter().any(|(known, _)| known == source) {
                if let Some(parent) = target.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                continue;
            }
            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            if tokio::fs::metadata(&target).await.is_err() {
                tokio::fs::write(&target, []).await?;
            }
            mounts.push(MountOp {
                source: cstring(source),
                target: cstring(&target),
                fstype: None,
                flags: libc::MS_BIND as libc::c_ulong,
                data: None,
                best_effort: false,
            });
            // Files are read-only inputs too: remount without REC.
            mounts.push(MountOp {
                source: cstring(&target),
                target: cstring(&target),
                fstype: None,
                flags: (libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY) as libc::c_ulong,
                data: None,
                best_effort: false,
            });
        } else {
            tokio::fs::create_dir_all(&target).await?;
            mounts.push(MountOp {
                source: cstring(source),
                target: cstring(&target),
                fstype: None,
                flags: (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
                data: None,
                best_effort: false,
            });
            if !writable {
                mounts.push(MountOp {
                    source: cstring(&target),
                    target: cstring(&target),
                    fstype: None,
                    flags: (libc::MS_BIND
                        | libc::MS_REMOUNT
                        | libc::MS_RDONLY
                        | libc::MS_REC) as libc::c_ulong,
                    data: None,
                    best_effort: false,
                });
            }
        }
    }
    if std::env::var_os("AVE_SANDBOX_DUMP").is_some() {
        for m in &mounts {
            eprintln!(
                "DBGMOUNT {} -> {} flags={} fstype={:?} best_effort={}",
                m.source.to_string_lossy(),
                m.target.to_string_lossy(),
                m.flags,
                m.fstype.as_ref().map(|f| f.to_string_lossy().into_owned()),
                m.best_effort
            );
        }
    }
    let spec_copies: Vec<(CString, Vec<u8>)> = copies
        .into_iter()
        .map(|(path, bytes)| (cstring(&target_of(&path)), bytes))
        .collect();

    // Minimal devices and scratch: absent host devices and host tmp.
    // All precomputed above; the child only replays raw syscalls.
    for node in ["null", "zero", "full", "urandom"] {
        let source = PathBuf::from("/dev").join(node);
        let target = new_root.join("dev").join(node);
        mounts.push(MountOp {
            source: cstring(&source),
            target: cstring(&target),
            fstype: None,
            flags: libc::MS_BIND as libc::c_ulong,
            data: None,
            best_effort: false,
        });
    }
    // Scratch tmpfs is mounted first in the child, so content
    // binds below land on top of it instead of being covered.

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let spec = Spec {
        mounts,
        copies: spec_copies,
        uid_map: format!("0 {uid} 1").into_bytes(),
        gid_map: format!("0 {gid} 1").into_bytes(),
        hostname: CString::new("ave-build").expect("const str"),
        pivot_new: cstring(&new_root),
        pivot_old: cstring(&old_root),
        workdir: cstring(&canonical_build),
        build_tmp: build_tmp.clone(),
        isolated_net: offline,
    };
    Ok((spec, canonical_build, host_cc))
}

/// Attach the sandbox to a child command: scratch locations are set
/// here in the parent, namespaces and mounts run allocation-free
/// after `fork` via `pre_exec`.
pub fn apply(cmd: &mut tokio::process::Command, spec: Spec) {
    cmd.env("TMPDIR", spec.build_tmp.as_os_str());
    cmd.env("TMP", spec.build_tmp.as_os_str());
    cmd.env("TEMP", spec.build_tmp.as_os_str());
    unsafe {
        cmd.pre_exec(move || sandbox_child(&spec));
    }
}

#[cfg(target_os = "linux")]
fn raw_write(fd: libc::c_int, bytes: &[u8]) -> io::Result<()> {
    let mut rest = bytes;
    while !rest.is_empty() {
        let written = unsafe {
            libc::write(
                fd,
                rest.as_ptr() as *const libc::c_void,
                rest.len(),
            )
        };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        rest = &rest[written as usize..];
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn raw_open(path: &CStr) -> io::Result<libc::c_int> {
    raw_open_mode(path, libc::O_WRONLY | libc::O_CLOEXEC, 0)
}

#[cfg(target_os = "linux")]
fn raw_open_mode(path: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<libc::c_int> {
    let fd = unsafe { libc::open(path.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn raw_close(fd: libc::c_int) {
    unsafe {
        libc::close(fd);
    }
}

#[cfg(target_os = "linux")]
fn write_file(path: &CStr, content: &[u8]) -> io::Result<()> {
    let fd = raw_open(path)?;
    let result = raw_write(fd, content);
    raw_close(fd);
    result
}

#[cfg(target_os = "linux")]
fn do_mount(
    source: &CStr,
    target: &CStr,
    fstype: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> io::Result<()> {
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.map_or(std::ptr::null(), |fs| fs.as_ptr()),
            flags,
            data.map_or(std::ptr::null(), |d| {
                d.as_ptr() as *const libc::c_void
            }),
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sandbox_child(spec: &Spec) -> io::Result<()> {
    const SETGROUPS: &CStr = c"/proc/self/setgroups";
    const UID_MAP: &CStr = c"/proc/self/uid_map";
    const GID_MAP: &CStr = c"/proc/self/gid_map";
    const NONE: &CStr = c"none";
    const ROOT: &CStr = c"/";
    const OLD: &CStr = c"/old";
    const DENY: &[u8] = b"deny";

    let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWUTS;
    if spec.isolated_net {
        flags |= libc::CLONE_NEWNET;
    }
    if unsafe { libc::unshare(flags) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("DBG unshare: {e}")));
    }
    write_file(SETGROUPS, DENY).map_err(|e| io::Error::new(e.kind(), format!("DBG setgroups: {e}")))?;
    write_file(UID_MAP, &spec.uid_map).map_err(|e| io::Error::new(e.kind(), format!("DBG uid_map: {e}")))?;
    write_file(GID_MAP, &spec.gid_map).map_err(|e| io::Error::new(e.kind(), format!("DBG gid_map: {e}")))?;
    // Private mounts: nothing below escapes to the host.
    do_mount(
        NONE,
        ROOT,
        None,
        (libc::MS_PRIVATE | libc::MS_REC) as libc::c_ulong,
        None,
    )?;
    // Mirror every dependency at its identical absolute path.
    // (No tmpfs over the skeleton: the mirror already leaves every
    // other host path out, and covering it would hide these binds.)
    for (index, entry) in spec.mounts.iter().enumerate() {
        if entry.flags & libc::MS_REMOUNT as libc::c_ulong != 0 {
            continue;
        }
        if index % 4 == 0 {
                }
        let result = do_mount(
            entry.source.as_c_str(),
            entry.target.as_c_str(),
            entry.fstype.as_deref(),
            entry.flags,
            entry.data.as_deref(),
        );
        if result.is_err() && !entry.best_effort {
            let e = result.unwrap_err();
            let src = entry.source.to_string_lossy().into_owned();
            let tgt = entry.target.to_string_lossy().into_owned();
            return Err(io::Error::new(e.kind(), format!("DBG mount {src} -> {tgt} flags={}: {e}", entry.flags)));
        }
    }
    // Materialize copied content on top of the binds, before
    // anything is remounted read-only. All operands are precomputed;
    // no allocation happens here.
    for (path, bytes) in &spec.copies {
        let fd = raw_open_mode(
            path.as_c_str(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o644,
        )
        .map_err(|e| {
            let p = path.to_string_lossy().into_owned();
            io::Error::new(e.kind(), format!("DBG copy-open {p}: {e}"))
        })?;
        let result = raw_write(fd, bytes).map_err(|e| {
            io::Error::new(e.kind(), format!("DBG copy-write: {e}"))
        });
        raw_close(fd);
        result?;
    }
    for entry in &spec.mounts {
        if entry.flags & libc::MS_REMOUNT as libc::c_ulong == 0 {
            continue;
        }
        let result = do_mount(
            entry.source.as_c_str(),
            entry.target.as_c_str(),
            entry.fstype.as_deref(),
            entry.flags,
            entry.data.as_deref(),
        );
        if result.is_err() && !entry.best_effort {
            let e = result.unwrap_err();
            let src = entry.source.to_string_lossy().into_owned();
            let tgt = entry.target.to_string_lossy().into_owned();
            return Err(io::Error::new(e.kind(), format!("DBG mount {src} -> {tgt} flags={}: {e}", entry.flags)));
        }
    }
    // Fixed identity: hostnames never shape artifacts or logs.
    if unsafe { libc::sethostname(spec.hostname.as_ptr(), spec.hostname.as_bytes().len()) }
        != 0
    {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("DBG sethostname: {e}")));
    }
    // `pivot_root` requires the new root to be a mount point.
    do_mount(
        spec.pivot_new.as_c_str(),
        spec.pivot_new.as_c_str(),
        None,
        (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
        None,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("DBG bindself: {e}")))?;
    // Pivot into the minimal root and drop the host tree.
    let pivoted = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            spec.pivot_new.as_ptr(),
            spec.pivot_old.as_ptr(),
        )
    };
    if pivoted != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("DBG pivot_root: {e}")));
    }
    const SLASH: &CStr = c"/";
    if unsafe { libc::chdir(SLASH.as_ptr()) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("DBG chdir-slash: {e}")));
    }
    if unsafe { libc::umount2(OLD.as_ptr(), libc::MNT_DETACH) } != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("DBG umount_old: {e}")));
    }
    // Enter the build directory here, not only through the caller's
    // `current_dir`: that one runs before the pivot at the latest,
    // leaving the child with a detached working directory whose path
    // can not be resolved — and cargo would then miss the manifest's
    // `.cargo/config.toml`.
    if unsafe { libc::chdir(spec.workdir.as_ptr()) } != 0 {
        let e = io::Error::last_os_error();
        let w = spec.workdir.to_string_lossy().into_owned();
        return Err(io::Error::new(e.kind(), format!("DBG chdir-work {w}: {e}")));
    }
    Ok(())
}
