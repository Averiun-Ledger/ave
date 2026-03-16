#!/usr/bin/env bash
# Generate TypeScript bindings from ave-common Rust types.
#
# Usage:
#   bash generate.sh            # regenerar tipos
#   npm run generate             # igual, desde common/ts/
#
# Publicar actualización a npm:
#   1. Modificar los tipos Rust en common/src/
#   2. bash generate.sh
#   3. npm version patch|minor|major
#   4. npm publish --access public
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINDINGS_DIR="$SCRIPT_DIR/src"
TMP_DIR="$(mktemp -d)"
RUST_WORKSPACE_DIR="$TMP_DIR/rust-workspace"

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

cleanup() {
  rm -rf "$TMP_DIR"
}

trap cleanup EXIT

echo "Generating TypeScript bindings from Rust types..."
setup_temp_workspace "$RUST_WORKSPACE_DIR"

rm -rf "$BINDINGS_DIR"
mkdir -p "$BINDINGS_DIR"

# Generate bindings via cargo test (ts-rs exports on test run)
# TS_RS_LARGE_INT=number ensures Rust u64/i64 types map to TypeScript number (not bigint)
TS_RS_EXPORT_DIR="$BINDINGS_DIR" \
  TS_RS_LARGE_INT=number \
  cargo test -p ave-common --features typescript \
  --manifest-path "$RUST_WORKSPACE_DIR/Cargo.toml" 2>&1

# Generate barrel index.ts re-exporting all generated types
echo "Creating index.ts..."
INDEX_FILE="$BINDINGS_DIR/index.ts"
: > "$INDEX_FILE"

# Export top-level types
for ts_file in "$BINDINGS_DIR"/*.ts; do
  filename="$(basename "$ts_file")"
  [ "$filename" = "index.ts" ] && continue
  module="${filename%.ts}"
  echo "export type { ${module} } from \"./${module}\";" >> "$INDEX_FILE"
done

# Export types from subdirectories (e.g. serde_json/JsonValue)
find "$BINDINGS_DIR" -mindepth 2 -name '*.ts' | sort | while read -r ts_file; do
  rel="${ts_file#"$BINDINGS_DIR"/}"
  module="${rel%.ts}"
  type_name="$(basename "$module")"
  echo "export type { ${type_name} } from \"./${module}\";" >> "$INDEX_FILE"
done

echo "Done! TypeScript bindings generated in $BINDINGS_DIR"
