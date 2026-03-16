#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PACKAGE_JSON="$SCRIPT_DIR/package.json"
SHOW_FULL_DIFF=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --full)
      SHOW_FULL_DIFF=1
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: bash check-published.sh [--full]"
      exit 64
      ;;
  esac
  shift
done

read_package_field() {
  local field="$1"
  node -e '
    const fs = require("fs");
    const pkg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.stdout.write(pkg[process.argv[2]]);
  ' "$PACKAGE_JSON" "$field"
}

extract_toml_section() {
  local section="$1"

  awk -v section="$section" '
    $0 == section { in_section = 1 }
    /^\[/ && $0 != section {
      if (in_section) {
        exit
      }
    }
    in_section { print }
  ' "$PROJECT_ROOT/Cargo.toml"
}

build_index_file() {
  local bindings_dir="$1"
  local index_file="$bindings_dir/index.ts"

  : > "$index_file"

  for ts_file in "$bindings_dir"/*.ts; do
    local filename module
    filename="$(basename "$ts_file")"
    [ "$filename" = "index.ts" ] && continue
    module="${filename%.ts}"
    echo "export type { ${module} } from \"./${module}\";" >> "$index_file"
  done

  find "$bindings_dir" -mindepth 2 -name '*.ts' | sort | while read -r ts_file; do
    local rel module type_name
    rel="${ts_file#"$bindings_dir"/}"
    module="${rel%.ts}"
    type_name="$(basename "$module")"
    echo "export type { ${type_name} } from \"./${module}\";" >> "$index_file"
  done
}

strip_ts_comments() {
  perl -0pe 's@/\*\*.*?\*/@@sg' "$1" | sed '/^[[:space:]]*\/\//d;/^[[:space:]]*$/d'
}

summarize_shape_change() {
  local published_file="$1"
  local generated_file="$2"

  node - "$published_file" "$generated_file" <<'NODE'
const fs = require("fs");

const [publishedPath, generatedPath] = process.argv.slice(2);
const published = fs.readFileSync(publishedPath, "utf8");
const generated = fs.readFileSync(generatedPath, "utf8");

function collectFields(source) {
  const matches = [...source.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*:/g)];
  const fields = matches
    .map((match) => match[1])
    .filter((name) => !["import", "from", "export", "type"].includes(name));
  return [...new Set(fields)].sort();
}

function collapseExport(source) {
  return source
    .split(/\n+/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("export "))
    .join(" ")
    .replace(/\s+/g, " ")
    .slice(0, 220);
}

const publishedFields = new Set(collectFields(published));
const generatedFields = new Set(collectFields(generated));

const added = [...generatedFields].filter((field) => !publishedFields.has(field));
const removed = [...publishedFields].filter((field) => !generatedFields.has(field));

if (added.length > 0) {
  console.log(`added fields: ${added.join(", ")}`);
}

if (removed.length > 0) {
  console.log(`removed fields: ${removed.join(", ")}`);
}

if (added.length === 0 && removed.length === 0) {
  console.log("type shape changed");
  console.log(`published: ${collapseExport(published)}`);
  console.log(`generated: ${collapseExport(generated)}`);
}
NODE
}

setup_temp_workspace() {
  local workspace_dir="$1"

  mkdir -p "$workspace_dir"
  cp -R "$PROJECT_ROOT/common" "$workspace_dir/"
  cp -R "$PROJECT_ROOT/identity" "$workspace_dir/"

  {
    printf '[workspace]\n'
    printf 'members = ["identity", "common"]\n'
    printf 'default-members = ["common"]\n'
    printf 'resolver = "2"\n\n'
    extract_toml_section '[workspace.package]'
    printf '\n'
    extract_toml_section '[workspace.dependencies]'
    printf '\n'
  } > "$workspace_dir/Cargo.toml"
}

PACKAGE_NAME="$(read_package_field name)"
PACKAGE_VERSION="$(read_package_field version)"
TMP_DIR="$(mktemp -d)"
RUST_WORKSPACE_DIR="$TMP_DIR/rust-workspace"
GENERATED_DIR="$TMP_DIR/generated/src"
PUBLISHED_DIR="$TMP_DIR/published"
ANALYSIS_DIR="$TMP_DIR/analysis"

cleanup() {
  rm -rf "$TMP_DIR"
}

trap cleanup EXIT

mkdir -p "$GENERATED_DIR" "$PUBLISHED_DIR" "$ANALYSIS_DIR"
setup_temp_workspace "$RUST_WORKSPACE_DIR"

echo "Generating fresh TypeScript bindings..."
TS_RS_EXPORT_DIR="$GENERATED_DIR" \
  TS_RS_LARGE_INT=number \
  cargo test -p ave-common --features typescript \
  --manifest-path "$RUST_WORKSPACE_DIR/Cargo.toml" >/dev/null

build_index_file "$GENERATED_DIR"

echo "Downloading published package ${PACKAGE_NAME}@${PACKAGE_VERSION}..."
pushd "$TMP_DIR" >/dev/null
if ! npm pack "${PACKAGE_NAME}@${PACKAGE_VERSION}" >/dev/null 2>&1; then
  echo "Published package ${PACKAGE_NAME}@${PACKAGE_VERSION} was not found in npm."
  echo "If the Rust types changed, publish a new package version after reviewing the diff."
  exit 2
fi
TARBALL="$(find "$TMP_DIR" -maxdepth 1 -name '*.tgz' | head -n 1)"
tar -xzf "$TARBALL" -C "$PUBLISHED_DIR"
popd >/dev/null

echo "Comparing generated bindings against the published package..."
declare -a api_changes=()
declare -a docs_only_changes=()
declare -A api_details=()
declare -A api_diffs=()

mapfile -t all_files < <(
  {
    find "$PUBLISHED_DIR/package/src" -type f -name '*.ts' -printf '%P\n'
    find "$GENERATED_DIR" -type f -name '*.ts' -printf '%P\n'
  } | sort -u
)

for rel_path in "${all_files[@]}"; do
  published_file="$PUBLISHED_DIR/package/src/$rel_path"
  generated_file="$GENERATED_DIR/$rel_path"
  published_norm="$ANALYSIS_DIR/${rel_path//\//__}.published.ts"
  generated_norm="$ANALYSIS_DIR/${rel_path//\//__}.generated.ts"

  if [ ! -f "$published_file" ]; then
    api_changes+=("$rel_path")
    api_details["$rel_path"]="new generated file"
    continue
  fi

  if [ ! -f "$generated_file" ]; then
    api_changes+=("$rel_path")
    api_details["$rel_path"]="file no longer generated"
    continue
  fi

  if cmp -s "$published_file" "$generated_file"; then
    continue
  fi

  strip_ts_comments "$published_file" > "$published_norm"
  strip_ts_comments "$generated_file" > "$generated_norm"

  if cmp -s "$published_norm" "$generated_norm"; then
    docs_only_changes+=("$rel_path")
    continue
  fi

  api_changes+=("$rel_path")
  api_details["$rel_path"]="$(summarize_shape_change "$published_norm" "$generated_norm")"

  if [ "$SHOW_FULL_DIFF" -eq 1 ]; then
    api_diffs["$rel_path"]="$(diff -u "$published_norm" "$generated_norm" || true)"
  fi
done

if [ "${#api_changes[@]}" -eq 0 ] && [ "${#docs_only_changes[@]}" -eq 0 ]; then
  echo "Bindings are in sync with the published npm package."
else
  if [ "${#api_changes[@]}" -gt 0 ]; then
    echo "API drift detected in ${#api_changes[@]} file(s):"
    for rel_path in "${api_changes[@]}"; do
      echo "- $rel_path"
      while IFS= read -r detail_line; do
        [ -n "$detail_line" ] && echo "  $detail_line"
      done <<< "${api_details[$rel_path]}"

      if [ "$SHOW_FULL_DIFF" -eq 1 ] && [ -n "${api_diffs[$rel_path]:-}" ]; then
        while IFS= read -r diff_line; do
          [ -n "$diff_line" ] && echo "  $diff_line"
        done <<< "${api_diffs[$rel_path]}"
      fi
    done
  fi

  if [ "${#docs_only_changes[@]}" -gt 0 ]; then
    echo "Docs/comment drift only in ${#docs_only_changes[@]} file(s):"
    for rel_path in "${docs_only_changes[@]}"; do
      echo "- $rel_path"
    done
  fi

  if [ "$SHOW_FULL_DIFF" -eq 0 ] && [ "${#api_changes[@]}" -gt 0 ]; then
    echo "Run with --full to print normalized diffs for the API changes."
  fi

  echo "Review the changes above, then publish a new npm version if the drift is intentional."
  exit 1
fi
