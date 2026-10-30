#!/usr/bin/env bash
# Ave node images: 3 variants x architectures, no emulation.
# SINGLE entry point: gate checks + seccomp profile + builds.
# There is deliberately no other script: checks must never be skipped
# by forgetting to run a separate file.
#
# Variants:
#   rocksdb-compiler  with pinned toolchain + vendor (ONLY compiler role)
#   rocksdb           no toolchain (light node)
#   sqlite            no toolchain (light node)
#
# Usage (flags or interactive menus — no args on a TTY asks by number;
# arch/variant answers accept comma-separated multi-select, e.g. 1,3):
#   ./build.sh [--prod] [--pin PIN] [--version VERSION]
#              [--arch amd64|arm64|all|local] [--variant V|all] [--push]
#              [--profile PROFILE] [--yes]
# Flags also accept comma lists (--arch amd64,arm64). Anything not
# passed by flag is asked interactively on a TTY; without a TTY
# (CI/pipe) experimental local defaults apply.
#   Experimental (default): free arch choice, `-exp` tag suffix, no push,
#      no manifests. Push an -exp tag by hand when another box needs it.
#   --prod (release): no suffix, every arch + every variant (unless
#      --arch/--variant narrow it), push + multi-arch manifests.
#      Requires DOCKER_USERNAME (registry namespace) and `docker login`.
# Defaults: PIN from ave-common governance DEFAULT_PIN, VERSION from
# ave/Cargo.toml, CARGO_PROFILE experimental (release with --prod).
set -euo pipefail

# Cache mounts (cargo registry + target) need BuildKit. Modern Docker
# enables it by default; this makes it explicit and loud otherwise.
export DOCKER_BUILDKIT=1

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
AVE_REPO="$WORKSPACE_ROOT/ave"

DOCKER_USERNAME="${DOCKER_USERNAME:-}"
DOCKER_REPO="${DOCKER_REPO:-ave-node}"

# Pinned moby/profiles commit for the seccomp base (review before bumping).
MOBY_PROFILES_COMMIT="${MOBY_PROFILES_COMMIT:-6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef}"
SECCOMP_JSON="$SCRIPT_DIR/seccomp-ave.json"
SECCOMP_NEED="mount pivot_root sethostname umount2 unshare"

PIN=""
VERSION=""
PUSH=false
ARCHS=""
VARIANT_SEL=""
PROD=""
CARGO_PROFILE=""
YES=false
EXP_SUFFIX="-exp"

usage() {
    echo "Usage: $0 [--prod] [--pin PIN] [--version VERSION] [--arch amd64|arm64|all|local] [--variant rocksdb-compiler|rocksdb|sqlite|all] [--profile PROFILE] [--push] [--yes]"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prod) PROD=true; shift ;;
        --pin) PIN="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --push) PUSH=true; shift ;;
        --arch) ARCHS="$2"; shift 2 ;;
        --variant) VARIANT_SEL="$2"; shift 2 ;;
        --profile) CARGO_PROFILE="$2"; shift 2 ;;
        --yes) YES=true; shift ;;
        -h|--help) usage 0 ;;
        *) echo "Unknown arg: $1" >&2; usage 1 ;;
    esac
done

read_choice() {
    local prompt="$1"
    local value
    read -r -p "$prompt" value
    printf '%s' "$value"
}

# Multi-select menu answer: "1,3" or "1 3". Prints the chosen numbers,
# deduplicated, space-separated. Anything else fails loud.
read_multi() {
    local prompt="$1" max="$2" raw sel n out
    raw="$(read_choice "$prompt")"
    raw="$(printf '%s' "$raw" | tr ',' ' ')"
    out=""
    for sel in $raw; do
        case "$sel" in
            ''|*[!0-9]*) echo "Error: invalid selection '$sel'." >&2; return 1 ;;
        esac
        n="$((10#$sel))"
        if [ "$n" -lt 1 ] || [ "$n" -gt "$max" ]; then
            echo "Error: option $n out of range (1-$max)." >&2; return 1
        fi
        case " $out " in
            *" $n "*) ;;
            *) out="$out $n" ;;
        esac
    done
    [ -n "$out" ] || { echo "Error: empty selection." >&2; return 1; }
    out="${out# }"
    printf '%s' "$out"
}

# Architecture answers (menu numbers or flag words) to build names.
# Accepts local/all/single names and explicit multi-select lists.
expand_archs() {
    local sel="$1" local_arch="$2" out="" a
    case "$sel" in
        local) printf '%s' "$local_arch"; return 0 ;;
        all) printf 'amd64 arm64'; return 0 ;;
    esac
    for a in $sel; do
        case "$a" in
            amd64|arm64)
                case " $out " in
                    *" $a "*) ;;
                    *) out="$out $a" ;;
                esac
                ;;
            local)
                echo "Error: 'local' can not be combined with other architectures." >&2
                return 1
                ;;
            *) echo "Error: --arch must be amd64, arm64, all or local (comma-separated ok)." >&2; return 1 ;;
        esac
    done
    [ -n "$out" ] || { echo "Error: empty architecture selection." >&2; return 1; }
    out="${out# }"
    printf '%s' "$out"
}

# Variant answers to build names. "all" expands to the three variants.
expand_variants() {
    local sel="$1" out="" v
    [ "$sel" = "all" ] && sel="rocksdb-compiler rocksdb sqlite"
    for v in $sel; do
        case "$v" in
            rocksdb-compiler|rocksdb|sqlite)
                case " $out " in
                    *" $v "*) ;;
                    *) out="$out $v" ;;
                esac
                ;;
            *) echo "Error: --variant must be rocksdb-compiler, rocksdb, sqlite or all (comma-separated ok)." >&2; return 1 ;;
        esac
    done
    [ -n "$out" ] || { echo "Error: empty variant selection." >&2; return 1; }
    out="${out# }"
    printf '%s' "$out"
}

# Flags accept the same comma lists as the interactive answers.
ARCHS="$(printf '%s' "$ARCHS" | tr ',' ' ')"
VARIANT_SEL="$(printf '%s' "$VARIANT_SEL" | tr ',' ' ')"

# Interactive numbered menus for anything not passed by flag.
# Multi-select with commas: "1,3".
if [ -t 0 ]; then
    if [ -z "$PROD" ]; then
        echo ""
        echo "Build selection:"
        echo "1) Experimental (local iteration: -exp suffix, no push)"
        echo "2) Production (release: no suffix, push + manifests)"
        case "$(read_choice "Select (1 or 2): ")" in
            1) PROD=false ;;
            2) PROD=true ;;
            *) echo "Error: invalid option." >&2; exit 1 ;;
        esac
    fi
    if [ -z "$ARCHS" ]; then
        echo ""
        echo "Architecture selection (several allowed: 1,2):"
        echo "1) AMD64 only"
        echo "2) ARM64 only"
        echo "3) Both (AMD64 + ARM64)"
        echo "4) Local arch only"
        picks="$(read_multi "Select: " 4)"
        ARCHS=""
        for pick in $picks; do
            case "$pick" in
                1) ARCHS="$ARCHS amd64" ;;
                2) ARCHS="$ARCHS arm64" ;;
                3) ARCHS="$ARCHS amd64 arm64" ;;
                4) ARCHS="$ARCHS local" ;;
            esac
        done
    fi
    if [ -z "$VARIANT_SEL" ]; then
        echo ""
        echo "Variant selection (several allowed: 1,3):"
        echo "1) rocksdb-compiler only (ONLY compiler role)"
        echo "2) rocksdb only (light node)"
        echo "3) sqlite only (light node)"
        echo "4) All variants"
        picks="$(read_multi "Select: " 4)"
        VARIANT_SEL=""
        for pick in $picks; do
            case "$pick" in
                1) VARIANT_SEL="$VARIANT_SEL rocksdb-compiler" ;;
                2) VARIANT_SEL="$VARIANT_SEL rocksdb" ;;
                3) VARIANT_SEL="$VARIANT_SEL sqlite" ;;
                4) VARIANT_SEL="$VARIANT_SEL all" ;;
            esac
        done
        case " $VARIANT_SEL " in
            *" all "*) VARIANT_SEL="all" ;;
        esac
    fi
else
    # Non-interactive (CI/pipe): experimental local defaults.
    [ -z "$PROD" ] && PROD=false
    [ -z "$ARCHS" ] && ARCHS="local"
    [ -z "$VARIANT_SEL" ] && VARIANT_SEL="all"
fi
VARIANT_SEL="$(expand_variants "$VARIANT_SEL")"

if [ "$PROD" = true ]; then
    # Release: no experimental suffix, push + manifests.
    EXP_SUFFIX=""
    [ -z "$CARGO_PROFILE" ] && CARGO_PROFILE="release"
    PUSH=true
    if [ -z "$DOCKER_USERNAME" ]; then
        echo "Error: production requires DOCKER_USERNAME (registry namespace)." >&2
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "Error: production requires a working docker login/daemon." >&2
        exit 1
    fi
else
    # Experimental: -exp suffix, never pushed by the script unless
    # --push is passed by hand (e.g. so another box can pull it).
    [ -z "$CARGO_PROFILE" ] && CARGO_PROFILE="experimental"
fi

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' is not installed." >&2
        exit 1
    fi
}

require_command docker
require_command cargo
require_command grep
require_command sha256sum
require_command python3
case " $VARIANT_SEL " in
    *" rocksdb-compiler "*) require_command rustup ;;
esac

fail() {
    echo "build.sh: FAIL: $*" >&2
    exit 1
}

# ============================================================================
# STEP 0. Pre-build gate (was verify-pins.sh): pins, toolchains, registry
# and frozen inputs must match before any layer is built. Loud on drift.
# ============================================================================
gate_pins() {
    local only_pin="${1:-}"
    local ave_repro="$WORKSPACE_ROOT/ave-reproducible-wasm"
    local sdk_dir="$WORKSPACE_ROOT/ave-contract-sdk"
    local common_dir="$AVE_REPO/common"

    [ -f "$ave_repro/config/toolchain.env" ] \
        || fail "toolchain.env not found at $ave_repro/config/toolchain.env"

    # shellcheck disable=SC1090
    . "$ave_repro/config/toolchain.env"
    echo "gate: toolchain.env loaded (RUST_VERSION=$RUST_VERSION)"

    # cargo-ave binaries match the pinned hashes (exact bytes, not --version).
    local arch want got bin
    for arch in amd64 arm64; do
        bin="$ave_repro/dist/cargo-ave-$arch"
        [ -f "$bin" ] || fail "missing $bin"
        case "$arch" in
            amd64) want="$CARGO_BINARY_SHA256_AMD64" ;;
            arm64) want="$CARGO_BINARY_SHA256_ARM64" ;;
        esac
        [ -n "${want:-}" ] || fail "no expected hash for $arch in toolchain.env"
        got="$(sha256sum "$bin" | cut -d' ' -f1)"
        [ "$got" = "$want" ] || fail "hash mismatch for $bin (got $got)"
        echo "gate: ok cargo-ave-$arch sha256"
    done

    # SDK version matches the pins that reference it.
    local sdk_version pin_count pin rustc_version pin_sdk reg_json
    sdk_version="$(grep -m1 '^version' "$sdk_dir/Cargo.toml" | cut -d'"' -f2)"
    [ -n "$sdk_version" ] || fail "cannot read SDK version"

    # Authority is the ave-common registry, read via its `pins`
    # example. ave-contracts/ave-pin is an off-chain audit tool: its
    # records are never build inputs and the build never requires
    # that checkout.
    reg_json="$(cd "$AVE_REPO" && cargo run -q -p ave-common --example pins)" \
        || fail "cannot read registry pins from ave-common"
    export GATE_REG_JSON="$reg_json"

    # Per-pin checks: rustup toolchain + wasm target.
    pin_count=0
    for pin in $(python3 -c "import json,os; print(' '.join(json.loads(os.environ['GATE_REG_JSON']).keys()))"); do
        if [ -n "$only_pin" ] && [ "$pin" != "$only_pin" ]; then
            continue
        fi
        pin_count=$((pin_count + 1))
        rustc_version="$(python3 -c "import json,os,sys; print(json.loads(os.environ['GATE_REG_JSON'])[sys.argv[1]]['rustc_version'])" "$pin")"
        pin_sdk="$(python3 -c "import json,os,sys; print(json.loads(os.environ['GATE_REG_JSON'])[sys.argv[1]]['sdk_version'])" "$pin")"
        [ "$pin_sdk" = "$sdk_version" ] \
            || fail "pin $pin sdk $pin_sdk != repo sdk $sdk_version"
        case " $VARIANT_SEL " in
            *" rocksdb-compiler "*)
                rustup toolchain list 2>/dev/null | grep -q "^$rustc_version" \
                    || fail "rustup toolchain $rustc_version (pin $pin) not installed"
                rustup target list --installed --toolchain "$rustc_version" 2>/dev/null | grep -q '^wasm32-unknown-unknown$' \
                    || fail "wasm32 target missing for toolchain $rustc_version (pin $pin)"
                ;;
            *)
                echo "gate: local contract toolchain not required without compiler variant"
                ;;
        esac
        echo "gate: ok pin $pin (rustc $rustc_version, sdk $pin_sdk)"
    done
    unset GATE_REG_JSON
    [ "$pin_count" -gt 0 ] || fail "no pins checked"

    # Frozen contract sources exist in ave-common.
    [ -f "$common_dir/pins/contract.rs" ] \
        || fail "missing common/pins/contract.rs"
    [ -f "$common_dir/pins/contract-v1.Cargo.lock" ] \
        || fail "missing common/pins/contract-v1.Cargo.lock"

    # Registry self-verification (lockfile bytes vs registry hashes,
    # template stability).
    (
        cd "$AVE_REPO"
        cargo test -q -p ave-common --lib governance 2>&1 | tail -3
    )
    echo "gate: ALL OK ($pin_count pin(s))"
}

# ============================================================================
# STEP 0b. Seccomp profile (was seccomp-make-profile.sh): the custom
# profile MUST exist and allow exactly the sandbox syscalls, or the
# sandbox dies with EPERM inside the container. Regenerated from the
# pinned moby base when missing or stale. Never skipped.
# ============================================================================
ensure_seccomp() {
    local stale=false
    if [ ! -f "$SECCOMP_JSON" ]; then
        echo "seccomp: missing $SECCOMP_JSON, regenerating"
        stale=true
    else
        local need
        for need in $SECCOMP_NEED; do
            if ! python3 -c "
import json,sys
p=json.load(open('$SECCOMP_JSON'))
rules=[r for r in p.get('syscalls',[]) if r.get('action')=='SCMP_ACT_ALLOW' and '$need' in r.get('names',[])]
sys.exit(0 if rules else 1)"; then
                echo "seccomp: unconditional allow for '$need' missing, regenerating"
                stale=true
                break
            fi
        done
    fi
    if [ "$stale" = true ]; then
        require_command curl
        local tmp
        tmp="$(mktemp)"
        trap 'rm -f "$tmp"' EXIT
        curl -fsSL --max-time 60 \
            "https://raw.githubusercontent.com/moby/profiles/${MOBY_PROFILES_COMMIT}/seccomp/default.json" \
            -o "$tmp" \
            || fail "cannot fetch moby seccomp base (commit $MOBY_PROFILES_COMMIT)"
        python3 - "$tmp" "$SECCOMP_JSON" <<'PYEOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    profile = json.load(f)
extra = {
    "names": ["mount", "pivot_root", "sethostname", "umount2", "unshare"],
    "action": "SCMP_ACT_ALLOW",
    "comment": "ave-build sandbox: user+mount namespaces, minimal root pivot, fixed hostname. No CAP_SYS_ADMIN required; every build runs unprivileged and every failure is loud.",
}
names = {n for rule in profile.get("syscalls", []) for n in rule.get("names", [])}
missing = [n for n in extra["names"] if n not in names and n not in ("pivot_root",)]
assert not missing, f"upstream profile lacks: {missing}"
profile.setdefault("syscalls", []).append(extra)
with open(dst, "w") as f:
    json.dump(profile, f, indent="\t")
    f.write("\n")
print(f"wrote {dst}: base + unconditional allow for {', '.join(extra['names'])}")
PYEOF
        trap - EXIT
        rm -f "$tmp"
    else
        echo "seccomp: ok $SECCOMP_JSON (allows: $SECCOMP_NEED)"
    fi
}

# 0. Fail fast: gate + seccomp before any layer is built.
if [ -n "$PIN" ]; then
    gate_pins "$PIN"
else
    gate_pins
fi
ensure_seccomp

# 1. Defaults from the single sources of truth.
if [ -z "$PIN" ]; then
    PIN="$(grep -m1 'pub const DEFAULT_PIN' "$AVE_REPO/common/src/governance.rs" | cut -d'"' -f2)"
    [ -n "$PIN" ] || { echo "Error: cannot read DEFAULT_PIN" >&2; exit 1; }
fi
RUSTC_VERSION="$(cd "$AVE_REPO" && cargo run -q -p ave-common --example pins | python3 -c "import json,sys; print(json.load(sys.stdin)['$PIN']['rustc_version'])")"
[ -n "$RUSTC_VERSION" ] || { echo "Error: no rustc_version for pin $PIN (registry)" >&2; exit 1; }
NODE_RUSTC_VERSION="$(grep -m1 '^RUST_VERSION=' "$WORKSPACE_ROOT/ave-reproducible-wasm/config/toolchain.env" | cut -d= -f2)"
[ -n "$NODE_RUSTC_VERSION" ] || { echo "Error: no RUST_VERSION in toolchain.env" >&2; exit 1; }
PIN_LOCKFILE="contract-v1.Cargo.lock"
if [ ! -f "$AVE_REPO/common/pins/$PIN_LOCKFILE" ]; then
    echo "Error: lockfile $PIN_LOCKFILE not found (pin $PIN)" >&2
    exit 1
fi
if [ -z "$VERSION" ]; then
    VERSION="$(grep -m1 '^version' "$AVE_REPO/Cargo.toml" | cut -d'"' -f2)"
    [ -n "$VERSION" ] || { echo "Error: cannot read workspace version" >&2; exit 1; }
fi

LOCAL_ARCH="$(uname -m)"
case "$LOCAL_ARCH" in
    x86_64) LOCAL_ARCH=amd64 ;;
    aarch64) LOCAL_ARCH=arm64 ;;
    *) echo "Error: unsupported host arch $LOCAL_ARCH" >&2; exit 1 ;;
esac
BUILD_ARCHS="$(expand_archs "$ARCHS" "$LOCAL_ARCH")"

echo ""
if [ "$PROD" = true ]; then
    echo "Production mode enabled:"
else
    echo "Experimental mode enabled:"
fi
echo "  - Version: $VERSION"
echo "  - Tag suffix: '${EXP_SUFFIX:-<none>}'"
echo "  - Cargo profile: $CARGO_PROFILE"
echo "  - Pin: $PIN (rustc $RUSTC_VERSION)"
echo "  - Node rustc: $NODE_RUSTC_VERSION (ave-reproducible toolchain.env)"
echo "  - Architectures: $BUILD_ARCHS (host: $LOCAL_ARCH)"
echo "  - Variant: $VARIANT_SEL"
echo "  - Push to Docker Hub: $([ "$PUSH" = true ] && echo yes || echo no)"
echo "  - Manifests: $([ "$PROD" = true ] && echo yes || echo no)"
echo ""

if [ -t 0 ] && [ "$YES" = false ]; then
    CONFIRM="$(read_choice "Continue? (y/n): ")"
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "Build cancelled."
        exit 0
    fi
fi

VARIANT_NAMES=(rocksdb-compiler rocksdb sqlite)
VARIANT_DOCKERFILES=(Dockerfile.node-rocksdb-compiler Dockerfile.node-rocksdb Dockerfile.node-sqlite)
VARIANT_FEATURES=("ext-sqlite rocksdb prometheus toolchain" "ext-sqlite rocksdb prometheus" "ext-sqlite sqlite prometheus")

fmt_duration() {
    local total="$1"
    printf '%dm%02ds' $((total / 60)) $((total % 60))
}

report_image_sizes() {
    local tag
    for tag in $BUILT_TAGS; do
        printf '%s ' "$tag"
        docker image inspect "$tag" --format 'content-bytes={{.Size}}'
    done
}

BUILD_TOTAL_SECS=0
BUILT_TAGS=""

# Static verification for images of a foreign arch (can not `docker
# run` them without emulation, which is prohibited): inspect every ELF
# in the exported rootfs and require the complete compiler tool set.
smoke_foreign_arch() {
    local tag="$1" arch="$2" variant="$3"
    local want_machine container
    case "$arch" in
        amd64) want_machine="62" ;;
        arm64) want_machine="183" ;;
        *) echo "Error: unsupported foreign arch $arch" >&2; exit 1 ;;
    esac
    [ "$(docker image inspect "$tag" --format '{{.Architecture}}')" = "$arch" ] \
        || { echo "Error: $tag reports wrong architecture" >&2; exit 1; }
    [ "$(docker image inspect "$tag" --format '{{.Config.User}}')" = "65532:65532" ] \
        || { echo "Error: $tag does not run as 65532:65532" >&2; exit 1; }
    container="$(docker create "$tag")"
    local tmp_script
    tmp_script="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$tmp_script'; docker rm '$container' >/dev/null 2>&1 || true" RETURN
    cat > "$tmp_script" <<'PYEOF'
import struct, sys, tarfile

want, variant, arch, rustc_version = sys.argv[1:]
machine_want = int(want)
gnu = {"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[arch]
rust = {"amd64": "x86_64-unknown-linux-gnu", "arm64": "aarch64-unknown-linux-gnu"}[arch]
required = {
    "usr/local/bin/ave-http",
    f"usr/lib/{gnu}/libssl.so.3",
}
if variant == "rocksdb-compiler":
    loader = "lib64/ld-linux-x86-64.so.2" if arch == "amd64" else "lib/ld-linux-aarch64.so.1"
    required.update({
        "usr/local/bin/cargo-ave-pinned",
        f"usr/local/rustup/toolchains/{rustc_version}-{rust}/bin/cargo",
        f"usr/local/rustup/toolchains/{rustc_version}-{rust}/bin/rustc",
        "usr/bin/gcc", "usr/bin/as", "usr/bin/ld", "usr/bin/ar",
        f"usr/libexec/gcc/{gnu}/14/cc1",
        f"usr/libexec/gcc/{gnu}/14/collect2",
        f"usr/libexec/gcc/{gnu}/14/lto1",
        f"lib/{gnu}/libc.so.6",
        loader,
    })

seen = set()
links = {}
checked = 0
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
    for member in archive:
        name = member.name.removeprefix("./")
        seen.add(name)
        assert not name.startswith("usr/local/cargo/registry"), f"registry cache leaked: {name}"
        assert not name.startswith("ave/target"), f"target cache leaked: {name}"
        if member.issym():
            links[name] = member.linkname
            continue
        if not member.isfile():
            continue
        source = archive.extractfile(member)
        if source is None:
            continue
        header = source.read(20)
        if header[:4] != b"\x7fELF":
            continue
        assert len(header) == 20, f"truncated ELF: {name}"
        machine = struct.unpack("<H", header[18:20])[0]
        assert machine == machine_want, f"{name}: ELF machine {machine} != {machine_want}"
        checked += 1

def resolve(path):
    # Follow rootfs symlinks (merged-usr: lib -> usr/lib, ...).
    # Link targets are relative to the link's directory.
    for _ in range(10):
        if path in seen:
            return path
        head, _, tail = path.partition("/")
        if head in links:
            target = links[head]
            path = (target + "/" + tail).replace("//", "/")
            if not path.startswith("/"):
                pass
            else:
                path = path.lstrip("/")
            continue
        return None
    return None

missing = sorted(p for p in required if resolve(p) is None)
assert not missing, f"missing required files: {missing}"
assert checked > 0, "no ELF files found"
print(f"rootfs ELF arch ok ({checked} files); required tool set present")
PYEOF
    docker export "$container" | python3 "$tmp_script" "$want_machine" "$variant" "$arch" "$RUSTC_VERSION"
    trap - RETURN
    docker rm "$container" >/dev/null
    rm -f "$tmp_script"
}

# Tag scheme: only the compiler image carries the contract pin
# (rust/sdk) — light variants never touch a toolchain. The pin's
# `_wasm32` suffix is dropped in tags: wasm32 is the only target,
# so it adds no information (the PIN itself is untouched).
image_tag() {
    local variant="$1" arch="$2" repo mid pin_tag
    repo="${DOCKER_USERNAME:+$DOCKER_USERNAME/}${DOCKER_REPO}"
    pin_tag="${PIN%_wasm32}"
    if [ "$variant" = "rocksdb-compiler" ]; then
        mid="${VERSION}-${variant}-${pin_tag}-${arch}${EXP_SUFFIX}"
    else
        mid="${VERSION}-${variant}-${arch}${EXP_SUFFIX}"
    fi
    printf '%s:%s' "$repo" "$mid"
}

build_variant_arch() {
    local variant="$1" dockerfile="$2" features="$3" arch="$4"
    local tag
    tag="$(image_tag "$variant" "$arch")"
    echo ""
    echo "### Building $tag"
    local start end secs
    start=$(date +%s)
    docker build \
        --platform "linux/$arch" \
        --build-arg "PIN=$PIN" \
        --build-arg "PIN_LOCKFILE=$PIN_LOCKFILE" \
        --build-arg "RUSTC_VERSION=$RUSTC_VERSION" \
        --build-arg "NODE_RUSTC_VERSION=$NODE_RUSTC_VERSION" \
        --build-arg "CARGO_PROFILE=$CARGO_PROFILE" \
        --build-arg "FEATURES=$features" \
        --target "$arch" \
        --tag "$tag" \
        --file "$SCRIPT_DIR/$dockerfile" \
        "$WORKSPACE_ROOT"
    echo "### Smoke test $tag"
    if [ "$arch" = "$LOCAL_ARCH" ]; then
        if docker run --rm "$tag" --help 2>&1 | grep -qi "shared librar"; then
            echo "Error: missing shared libraries in $tag" >&2
            exit 1
        fi
        docker run --rm "$tag" --help >/dev/null
        # Compiler images must also run the pinned cargo (libcurl closure).
        if [ "$variant" = "rocksdb-compiler" ]; then
            docker run --rm --entrypoint /usr/local/bin/cargo-ave-pinned "$tag" --version >/dev/null \
                || { echo "Error: cargo-ave-pinned broken in $tag" >&2; exit 1; }
            docker run --rm --entrypoint /usr/local/bin/rustc "$tag" --version >/dev/null \
                || { echo "Error: target rustc broken in $tag" >&2; exit 1; }
            docker run --rm --entrypoint /usr/local/bin/cargo "$tag" --version >/dev/null \
                || { echo "Error: target cargo broken in $tag" >&2; exit 1; }
        fi
    else
        smoke_foreign_arch "$tag" "$arch" "$variant"
    fi
    end=$(date +%s)
    secs=$((end - start))
    BUILD_TOTAL_SECS=$((BUILD_TOTAL_SECS + secs))
    echo "### OK $tag ($(fmt_duration "$secs"))"
    BUILT_TAGS="$BUILT_TAGS $tag"
    if [ "$PUSH" = true ]; then
        docker push "$tag"
    fi
}

MANIFESTS=""
for i in "${!VARIANT_NAMES[@]}"; do
    variant="${VARIANT_NAMES[$i]}"
    dockerfile="${VARIANT_DOCKERFILES[$i]}"
    features="${VARIANT_FEATURES[$i]}"
    case " $VARIANT_SEL " in
        *" $variant "*) ;;
        *) continue ;;
    esac
    for arch in $BUILD_ARCHS; do
        build_variant_arch "$variant" "$dockerfile" "$features" "$arch"
        MANIFESTS="$MANIFESTS $(image_tag "$variant" "$arch")"
    done
done

if [ "$PROD" = true ]; then
    for variant in $VARIANT_SEL; do
        if [ "$variant" = "rocksdb-compiler" ]; then
            pin_mid="-${PIN%_wasm32}"
        else
            pin_mid=""
        fi
        if [ -n "$DOCKER_USERNAME" ]; then
            base_tag="${DOCKER_USERNAME}/${DOCKER_REPO}:${VERSION}-${variant}${pin_mid}"
        else
            base_tag="${DOCKER_REPO}:${VERSION}-${variant}${pin_mid}"
        fi
        echo ""
        echo "### Multi-arch manifest $base_tag"
        docker manifest rm "$base_tag" 2>/dev/null || true
        args=""
        for arch in $BUILD_ARCHS; do
            args="$args ${base_tag}-${arch}"
        done
        # shellcheck disable=SC2086
        docker manifest create "$base_tag" $args
        for arch in $BUILD_ARCHS; do
            docker manifest annotate "$base_tag" "${base_tag}-${arch}" --os linux --arch "$arch"
        done
        docker manifest push "$base_tag"
    done
fi

echo ""
echo "Done in $(fmt_duration "$BUILD_TOTAL_SECS"). Images (not pushed unless --push):"
report_image_sizes
echo ""
echo "Run a compiler node (seccomp=unconfined is the pragmatic default:"
echo "the default Docker profile denies unshare/mount/pivot_root and the"
echo "build sandbox fails loud with it; the custom profile below is only"
echo "for paranoid deployments):"
echo ""
echo "  docker run -d --name ave-node \\"
echo "    --read-only --tmpfs /tmp --tmpfs /ave/tmp \\"
echo "    --cap-drop ALL --security-opt no-new-privileges \\"
echo "    --security-opt seccomp=unconfined \\"
echo "    # Paranoid only: --security-opt seccomp=$SCRIPT_DIR/seccomp-ave.json \\"
echo "    --user 65532:65532 --memory 8g --cpus 4 \\"
echo "    -v ave-contracts:/contracts --network host \\"
echo "    # Map volumes onto the FIXED container paths (production configs"
echo "    # can not move them: /contracts, /db/*, /keys, /logs; tests keep"
echo "    # custom dirs via the test feature). Named volumes persist across"
echo "    # 'docker rm'; make them writable by 65532 once."
if [ -n "$DOCKER_USERNAME" ]; then
    echo "    ${DOCKER_USERNAME}/${DOCKER_REPO}:${VERSION}-rocksdb-compiler-${PIN%_wasm32}-<arch>"
else
    echo "    ${DOCKER_REPO}:${VERSION}-rocksdb-compiler-${PIN%_wasm32}-<arch>"
fi
